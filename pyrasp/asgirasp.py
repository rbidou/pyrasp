import json
import re
import time
from urllib.parse import parse_qs, unquote

from .pyrasp import PyRASP, DlpStreamScanner, parse_content_disposition

# DATA GLOBALS
try:
    from .pyrasp_data import ATTACKS_CHECKS
except:
    from pyrasp.pyrasp_data import ATTACKS_CHECKS


class ResponseBlocked(Exception):
    """Raised into the wrapped app when it keeps sending after its response was blocked"""


class AsgiRASP(PyRASP):

    FORM_TYPE = 'application/x-www-form-urlencoded'
    MULTIPART_TYPE = 'multipart/form-data'
    BODY_KEY = 'pyrasp.body'

    def __init__(self, app = None, template = 'default', conf = None, params = {}, key = None, cloud_url = None):
        self.PLATFORM = 'ASGI'
        super().__init__(app, template, conf, params, key, cloud_url)

    async def __call__(self, scope, receive, send):

        # Lifespan and websocket traffic: not an HTTP request / response
        if scope.get('type') != 'http':
            await self.asgi_app(scope, receive, send)
            return

        # Request body: read once, kept for the checks, replayed to the app
        scope = dict(scope)
        body, disconnect = await self.read_body(receive)
        scope[self.BODY_KEY] = body
        receive = self.replay_receive(body, disconnect, receive)

        process_outbound = True
        inbound_attack_type = None
        inbound_check = None

        # Main params
        (host, request_method, request_path, source_ip, timestamp) = self.get_params(scope)

        # JA4H fingerprint
        ja4h_fingerprint = None
        if self.LOG_JA4H_FINGERPRINT or self.SECURITY_CHECKS.get('bots'):
            ja4h_fingerprint = self.calculate_ja4h_fingerprint(scope)

        ####################################################
        # INBOUND
        ####################################################

        inbound_attack = self.check_inbound_attacks( host, request_method, request_path, source_ip, timestamp, scope, ja4h_fingerprint=ja4h_fingerprint )

        if inbound_attack:
            inbound_attack_type = inbound_attack['type']
            inbound_check = ATTACKS_CHECKS[inbound_attack_type]
            self.handle_attack(inbound_attack, host, request_path, source_ip, timestamp, ja4h_fingerprint=ja4h_fingerprint)
            if self.SECURITY_CHECKS.get(inbound_check) != 3:
                process_outbound = False

        ####################################################
        # OUTBOUND DECISION
        ####################################################

        # Run once per request, either when the response starts (streamed,
        # not inspectable) or when its body is complete (buffered)
        def decide(content, app_response):

            status_code = app_response.status_code if app_response is not None else 200
            security_check = inbound_check

            outbound_attack = self.check_outbound_attacks( content, request_path, source_ip, timestamp, status_code, inbound_attack_type )

            if outbound_attack:
                security_check = ATTACKS_CHECKS[outbound_attack['type']]
                self.handle_attack(outbound_attack, host, request_path, source_ip, timestamp, ja4h_fingerprint=ja4h_fingerprint)

            attack = outbound_attack or inbound_attack
            log_only = bool(security_check) and self.SECURITY_CHECKS.get(security_check) == 3

            return self.process_response(app_response, attack, log_only = log_only)

        # Inbound block: the application is never called
        if not process_outbound:
            response = decide(None, None)
            if not isinstance(response, AsgiResponse):
                response = self.build_error_response()
            await self.send_response(response, send)
            return

        ####################################################
        # APPLICATION
        ####################################################

        state = {
            'start': None,          # held http.response.start message
            'response': None,       # AsgiResponse view of it, for the checks
            'mode': None,           # None -> 'buffer' | 'stream' | 'blocked'
            'chunks': [],
            'size': 0,
            'scanner': None,        # DLP scanner of a body not inspected as a whole
        }

        # Pass-through body chunk: a leak ends the response cleanly before it
        async def send_body(message):

            scanner = state['scanner']

            if scanner is not None and scanner.scan(message.get('body', b'') or b''):
                state['mode'] = 'blocked'
                await send({'type': 'http.response.body', 'body': b'', 'more_body': False})
                raise ResponseBlocked()

            await send(message)

        async def resolve(content, flush = None, more_body = False):

            app_response = state['response']
            response = decide(content, app_response)

            # Pass-through: release the held start message, then what was buffered
            if response is app_response:
                start = dict(state['start'])
                start['headers'] = self.finalize_headers(response.headers).to_asgi()
                state['mode'] = 'stream'
                if content is None and self.should_scan_stream(response.headers.get('content-type'), response.headers.get('content-encoding')):
                    state['scanner'] = DlpStreamScanner(self, (host, request_path, source_ip, timestamp, ja4h_fingerprint))
                await send(start)
                if flush is not None:
                    await send_body({'type': 'http.response.body', 'body': flush, 'more_body': more_body})

            # Block or redirect: nothing from the app reaches the client
            else:
                state['mode'] = 'blocked'
                if not isinstance(response, AsgiResponse):
                    response = self.build_error_response()
                await self.send_response(response, send)

            state['chunks'] = []

        async def rasp_send(message):

            message_type = message.get('type')
            mode = state['mode']

            if mode == 'blocked':
                # Stops the app producing a response nobody will receive
                # (infinite SSE generators, large streams...)
                raise ResponseBlocked()

            if mode == 'stream':
                if message_type == 'http.response.body':
                    await send_body(message)
                else:
                    await send(message)
                return

            if message_type == 'http.response.start':

                if mode is not None:
                    raise RuntimeError('ASGI: http.response.start sent twice')

                headers = AsgiHeaders.from_asgi(message.get('headers', []))
                state['start'] = message
                state['response'] = AsgiResponse(None, message.get('status', 200), headers)

                if self.should_inspect_response(headers.get('content-type'), headers.get('content-length'), headers.get('content-encoding')) and not message.get('trailers', False):
                    # Held back: the response may still be blocked by an outbound check
                    state['mode'] = 'buffer'
                else:
                    # Not inspectable: decide now on status and headers, then stream
                    await resolve(None)
                return

            if mode is None:
                raise RuntimeError(f'ASGI: {message_type} sent before http.response.start')

            # mode == 'buffer'
            if message_type == 'http.response.body':

                chunk = message.get('body', b'') or b''
                state['chunks'].append(chunk)
                state['size'] += len(chunk)

                if not message.get('more_body', False):
                    body = b''.join(state['chunks'])
                    await resolve(self.decode_response_body(body), flush = body)

                elif state['size'] > self.MAX_BODY_INSPECT:
                    # Declared length was wrong: give up inspection, stream the rest
                    await resolve(None, flush = b''.join(state['chunks']), more_body = True)

                return

            # http.response.pathsend, zerocopysend...: no body to inspect
            pending = b''.join(state['chunks'])
            await resolve(None, flush = pending if pending else None, more_body = True)
            if state['mode'] == 'stream':
                await send(message)

        try:
            await self.asgi_app(scope, receive, rasp_send)

        except ResponseBlocked:
            return

        except Exception:
            if state['mode'] == 'blocked':
                # The app wrapped or re-raised our stop signal: response already sent
                return
            if state['mode'] in (None, 'buffer'):
                self.check_outbound_attacks( None, request_path, source_ip, timestamp, 500, inbound_attack_type )
            raise

        ####################################################
        # RESPONSE
        ####################################################

        # The wrapped app returned without ever starting a response
        if state['mode'] is None:
            await self.send_response(self.build_error_response(), send)

        # The app returned without a final body message: settle what was sent
        elif state['mode'] == 'buffer':
            body = b''.join(state['chunks'])
            await resolve(self.decode_response_body(body), flush = body)

    def register_security_checks(self, app):
        if not callable(app):
            raise TypeError('AsgiRASP must wrap an ASGI application')
        self.asgi_app = app

    ####################################################
    # ROUTES
    ####################################################

    # Not supported at ASGI level
    def get_app_routes(self, app):
        return {}

    ####################################################
    # SECURITY FUNCTIONS
    ####################################################

    # Not supported at ASGI level
    def check_route(self, request, request_method, request_path):
        return None

    ####################################################
    # RESPONSE PROCESSING
    ####################################################

    def build_block_response(self, status_code, content):

        if isinstance(content, str):
            content = content.encode('utf-8')

        headers = [
            ('content-type', 'text/html; charset=utf-8'),
            ('content-length', str(len(content))),
        ]

        return AsgiResponse(content, status_code, headers)

    def build_redirect_response(self, status_code, content):

        headers = [
            ('location', content),
            ('content-type', 'text/html; charset=utf-8'),
            ('content-length', '0'),
            ('cache-control', 'no-store, no-cache, must-revalidate'),
            ('pragma', 'no-cache'),
        ]

        return AsgiResponse(b'', status_code, headers)

    def build_error_response(self):

        headers = [
            ('content-type', 'text/plain'),
            ('content-length', '0'),
        ]

        return AsgiResponse(b'', 500, headers)

    def change_server(self, response):
        if response is not None:
            response.headers['Server'] = self.SERVER_HEADER
        return response

    def finalize_headers(self, headers):

        headers = AsgiHeaders(headers)

        if getattr(self, 'CHANGE_SERVER', False):
            headers = AsgiHeaders((n, v) for n, v in headers if n.lower() != 'server')
            headers.append(('server', getattr(self, 'SERVER_HEADER', 'Apache')))

        return headers

    async def send_response(self, response, send):

        await send({
            'type': 'http.response.start',
            'status': response.status_code,
            'headers': self.finalize_headers(response.headers).to_asgi(),
        })
        await send({
            'type': 'http.response.body',
            'body': response.body,
            'more_body': False,
        })

    ####################################################
    # REQUEST BODY
    ####################################################

    async def read_body(self, receive):
        """Drains the request body. Returns (body, disconnect message or None)"""

        chunks = []

        while True:
            message = await receive()
            message_type = message.get('type')

            if message_type == 'http.disconnect':
                return b''.join(chunks), message

            if message_type != 'http.request':
                continue

            chunks.append(message.get('body', b'') or b'')

            if not message.get('more_body', False):
                return b''.join(chunks), None

    def replay_receive(self, body, disconnect, receive):

        replayed = {'done': False}

        async def rasp_receive():
            if not replayed['done']:
                replayed['done'] = True
                return {'type': 'http.request', 'body': body, 'more_body': False}
            if disconnect is not None:
                return disconnect
            # Nothing left to read: the server answers with http.disconnect
            return await receive()

        return rasp_receive

    ####################################################
    # UTILS
    ####################################################

    # Get request params
    def get_params(self, scope):

        request_path = scope.get('path', '')
        request_method = scope.get('method')
        source_ip = self.get_ip(scope)
        timestamp = time.time()

        host = self.get_header(scope, 'host') or None
        if host is None and scope.get('server'):
            server_host, server_port = scope['server'][0], scope['server'][1]
            host = f'{server_host}:{server_port}' if server_port else server_host

        return (host, request_method, request_path, source_ip, timestamp)

    def get_request_path(self, scope):

        request_path = scope.get('path', '')
        path_elements = request_path.split('/') or []

        return path_elements

    def get_query_string(self, scope):

        query_string = {}

        qs = self.to_text(scope.get('query_string', b''))

        if qs:
            try:
                query_string = parse_qs(qs, keep_blank_values=True, errors='replace')
            except Exception:
                query_string = {}

        return query_string

    def get_request_headers(self, scope):

        headers = {}

        for raw_name, raw_value in scope.get('headers', []):
            name = self.to_text(raw_name).lower()
            value = self.to_text(raw_value)
            if name in headers:
                separator = '; ' if name == 'cookie' else ', '
                headers[name] = headers[name] + separator + value
            else:
                headers[name] = value

        return headers

    def get_header(self, scope, name):
        return self.get_request_headers(scope).get(name.lower(), '')

    def get_body_data(self, scope):
        return scope.get(self.BODY_KEY, b'')

    def get_content_type(self, scope):
        """content-type header -> (mime_type, {parameters})"""

        raw = self.get_header(scope, 'content-type')
        parts = raw.split(';')
        mime_type = parts[0].strip().lower()

        parameters = {}
        for part in parts[1:]:
            if '=' not in part:
                continue
            name, value = part.split('=', 1)
            value = value.strip()
            if len(value) > 1 and value[0] == value[-1] and value[0] in '"\'':
                value = value[1:-1]
            parameters[name.strip().lower()] = value

        return mime_type, parameters

    def get_posted_data(self, scope):

        posted_data = {}

        mime_type, _ = self.get_content_type(scope)

        # Form bodies only: a JSON body parsed by parse_qs would land the
        # whole payload in a variable NAME instead of a value
        if mime_type == self.FORM_TYPE:

            body = self.get_body_data(scope)

            try:
                posted_data = parse_qs(
                    body.decode('utf-8', errors='ignore'),
                    keep_blank_values=True
                )
            except Exception:
                pass

        # Multipart text fields: same location as urlencoded variables
        elif mime_type == self.MULTIPART_TYPE:

            for name, value in self.get_multipart_parts(scope, files=False):
                posted_data.setdefault(name, []).append(value)

        return posted_data

    def get_json_data(self, scope):

        json_keys = []
        json_values = []

        mime_type, _ = self.get_content_type(scope)

        if not (mime_type == 'application/json' or mime_type.endswith('+json')):
            return (json_keys, json_values)

        body = self.get_body_data(scope)

        try:
            json_data = json.loads(body)
            (json_keys, json_values) = self.analyze_json(json_data)
        except Exception:
            pass

        return (json_keys, json_values)

    def get_multipart_parts(self, scope, files = True):
        """
        Splits a multipart body.
        files=True  -> [ (filename, content_length), ... ] for file parts
        files=False -> [ (field_name, value), ... ] for text parts
        """

        parts = []

        mime_type, parameters = self.get_content_type(scope)
        if mime_type != self.MULTIPART_TYPE:
            return parts

        boundary = parameters.get('boundary', '')
        if not boundary:
            return parts

        raw = self.get_body_data(scope)
        if not raw:
            return parts

        boundary = boundary.encode('utf-8', 'ignore')

        # The CRLF preceding a delimiter belongs to the delimiter, not to the
        # part content: splitting this way keeps binary uploads intact
        delimiter = b'\r\n--' + boundary
        body = b'\r\n' + raw
        separator = b'\r\n\r\n'

        if delimiter not in body:                   # bare-LF client or proxy
            delimiter = b'\n--' + boundary
            body = b'\n' + raw
            separator = b'\n\n'

        for segment in body.split(delimiter)[1:]:

            if segment.startswith(b'--'):           # closing delimiter
                break

            split = segment.split(separator, 1)
            if len(split) != 2:
                continue

            raw_headers, content = split

            try:
                headers = raw_headers.decode('utf-8', errors='ignore')
            except Exception:
                continue

            disposition = ''
            for line in headers.replace('\r\n', '\n').split('\n'):
                if line.lower().lstrip().startswith('content-disposition:'):
                    disposition = line
                    break

            if not disposition:
                continue

            field_name, filenames = parse_content_disposition(disposition)

            # A part is a file when it declares a file name (filename or filename*)
            is_file = len(filenames) > 0

            if is_file != files:
                continue

            if files:

                # File input left empty by the user: no file sent
                if filenames == [''] and len(content) == 0:
                    continue

                for filename in filenames:
                    parts.append((filename, len(content)))

            else:

                if field_name is None:
                    continue

                value = content
                if value.endswith(b'\r\n'):
                    value = value[:-2]
                elif value.endswith(b'\n'):
                    value = value[:-1]

                parts.append((field_name, value.decode('utf-8', errors='ignore')))

        return parts

    def get_files(self, scope):

        files = [[name, size] for name, size in self.get_multipart_parts(scope)]

        return files

    def get_ip(self, scope):
        if getattr(self, 'TRUST_PROXY_HEADERS', True):
            forwarded = self.get_header(scope, 'x-forwarded-for')
            if forwarded:
                return forwarded.split(',')[0].strip()
        client = scope.get('client')
        if client:
            return client[0]
        return '0.0.0.0'

    def to_text(self, value):

        if value is None:
            return ''

        if isinstance(value, (bytes, bytearray)):
            try:
                return bytes(value).decode('utf-8')
            except UnicodeDecodeError:
                return bytes(value).decode('latin-1', errors='replace')

        if not isinstance(value, str):
            return str(value)

        return value

    ####################################################
    # JA4H FINGERPRINTING
    ####################################################

    def get_ja4h_params(self, scope):

        method = scope.get('method')
        version = 'HTTP/' + scope.get('http_version', '1.1')
        headers = self.get_ja4h_headers_list(scope)

        return (method, version, headers)

    def get_ja4h_headers_list(self, scope):

        headers = []

        for raw_name, raw_value in scope.get('headers', []):
            headers.append([ self.to_text(raw_name).lower(), self.to_text(raw_value).lower() ])

        return headers


class AsgiHeaders(list):
    """
    ASGI headers as a list of (name, value) str tuples, with dict-style
    access so change_server() and friends work unchanged.
    Latin-1 both ways: pass-through headers round-trip byte for byte.
    """

    @classmethod
    def from_asgi(cls, raw_headers):
        return cls(
            (bytes(name).decode('latin-1'), bytes(value).decode('latin-1'))
            for name, value in raw_headers
        )

    def to_asgi(self):
        encoded = []
        for name, value in self:
            value = str(value)
            try:
                raw_value = value.encode('latin-1')
            except UnicodeEncodeError:
                raw_value = value.encode('utf-8')
            encoded.append((str(name).lower().encode('latin-1'), raw_value))
        return encoded

    def _index(self, key):
        lowered = key.lower()
        for index, (name, _) in enumerate(self):
            if name.lower() == lowered:
                return index
        return None

    def __getitem__(self, key):
        if isinstance(key, str):
            index = self._index(key)
            if index is None:
                raise KeyError(key)
            return list.__getitem__(self, index)[1]
        return list.__getitem__(self, key)

    def __setitem__(self, key, value):
        if isinstance(key, str):
            index = self._index(key)
            if index is None:
                self.append((key, value))
            else:
                list.__setitem__(self, index, (key, value))
            return
        list.__setitem__(self, key, value)

    def __delitem__(self, key):
        if isinstance(key, str):
            index = self._index(key)
            if index is None:
                raise KeyError(key)
            list.__delitem__(self, index)
            return
        list.__delitem__(self, key)

    def __contains__(self, key):
        if isinstance(key, str):
            return self._index(key) is not None
        return list.__contains__(self, key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def pop(self, key, default=None):
        if isinstance(key, str):
            index = self._index(key)
            if index is None:
                return default
            return list.pop(self, index)[1]
        return list.pop(self, key)

    def update(self, other):
        items = other.items() if hasattr(other, 'items') else other
        for name, value in items:
            self[name] = value


class AsgiResponse:
    """
    Response view exposing status_code / headers, so it can go through
    process_response() like a framework response object.
    """

    def __init__(self, body, status_code, headers):

        if body is None:
            self.body = b''
        elif isinstance(body, str):
            self.body = body.encode('utf-8')
        else:
            self.body = bytes(body)

        try:
            self.status_code = int(status_code)
        except (TypeError, ValueError):
            self.status_code = 500

        self.headers = AsgiHeaders(headers)