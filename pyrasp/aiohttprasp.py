import asyncio
import json
import re
import time
from urllib.parse import parse_qs, unquote

from aiohttp import web
from aiohttp.streams import StreamReader

from .pyrasp import PyRASP, DlpStreamScanner, parse_content_disposition

# DATA GLOBALS
try:
    from .pyrasp_data import ATTACKS_CHECKS, ATTACK_PATH
except ImportError:
    from pyrasp.pyrasp_data import ATTACKS_CHECKS, ATTACK_PATH

# Request / response storage keys for streamed responses scanning
CONTEXT_KEY = 'pyrasp.context'
STREAM_KEY = 'pyrasp.stream'
SCANNER_KEY = 'pyrasp.scanner'
CUT_KEY = 'pyrasp.cut'

class StreamBlocked(ConnectionResetError):
    """Raised into the handler when a leak cut its streamed response"""

STREAM_WRITE = web.StreamResponse.write

# StreamResponse.write() replacement: chunks of responses with a scanner are
# checked before being sent. A leak ends the response cleanly without it.
async def scanned_write(response, data):

    scanner = response.get(SCANNER_KEY)

    if response.get(CUT_KEY):
        raise StreamBlocked()

    if scanner is not None and scanner.scan(data):
        response[CUT_KEY] = True
        await response.write_eof()
        raise StreamBlocked()

    await STREAM_WRITE(response, data)

class AiohttpRASP(PyRASP):

    FORM_TYPE = 'application/x-www-form-urlencoded'
    MULTIPART_TYPE = 'multipart/form-data'
    BODY_KEY = 'pyrasp.body'
    MAX_BODY_BUFFER = 16 * 1024 * 1024          # larger request bodies are not buffered (fail open)

    def __init__(self, app = None, template = 'default', conf = None, params = {}, key = None, cloud_url = None):
        self.PLATFORM = 'aiohttp'
        super().__init__(app, template, conf, params, key, cloud_url)

    def register_security_checks(self, app):
        if not isinstance(app, web.Application):
            raise TypeError('AiohttpRASP must wrap an aiohttp.web.Application')
        if app.frozen:
            raise RuntimeError('AiohttpRASP must be attached before the application starts')
        # Outermost middleware: sees every request, including 404/405
        app.middlewares.insert(0, self.middleware)
        # Handlers streaming with StreamResponse.write() bypass the middleware
        app.on_response_prepare.append(self.attach_stream_scanner)
        web.StreamResponse.write = scanned_write

    # Streamed responses (not web.Response): scanned chunk by chunk when text
    async def attach_stream_scanner(self, request, response):

        context = request.get(CONTEXT_KEY)

        if all([
            context is not None,
            not isinstance(response, web.Response),
            self.should_scan_stream(response.content_type, response.headers.get('Content-Encoding'))
        ]):
            response[SCANNER_KEY] = DlpStreamScanner(self, context)
            request[STREAM_KEY] = response

    ####################################################
    # MIDDLEWARE
    ####################################################

    @web.middleware
    async def middleware(self, request, handler):

        process_outbound = True
        inbound_attack_type = None
        log_only = False
        security_check = None

        # The body is read here, asynchronously, so that the synchronous
        # getters called by PyRASP can work on an in-memory copy
        await self.buffer_body(request)

        # Main params
        (host, request_method, request_path, source_ip, timestamp) = self.get_params(request)

        # JA4H fingerprint
        ja4h_fingerprint = None
        if self.LOG_JA4H_FINGERPRINT or self.SECURITY_CHECKS.get('bots'):
            ja4h_fingerprint = self.calculate_ja4h_fingerprint(request)

        ####################################################
        # INBOUND
        ####################################################

        inbound_attack = self.check_inbound_attacks( host, request_method, request_path, source_ip, timestamp, request, ja4h_fingerprint=ja4h_fingerprint )

        if inbound_attack:
            inbound_attack_type = inbound_attack['type']
            security_check = ATTACKS_CHECKS[inbound_attack_type]
            self.handle_attack(inbound_attack, host, request_path, source_ip, timestamp, ja4h_fingerprint=ja4h_fingerprint)
            if self.SECURITY_CHECKS.get(security_check) != 3:
                process_outbound = False

        ####################################################
        # APPLICATION
        ####################################################

        app_response = None
        http_exception = None
        response_content = None
        status_code = 200

        if process_outbound:

            request[CONTEXT_KEY] = (host, request_path, source_ip, timestamp, ja4h_fingerprint)

            try:
                app_response = await handler(request)
            except StreamBlocked:
                app_response = request.get(STREAM_KEY)
            except web.HTTPException as exc:
                # 404, 405, redirects... raised by aiohttp routing or the handler
                http_exception = exc
                app_response = exc
            except Exception:
                self.check_outbound_attacks( None, request_path, source_ip, timestamp, 500, inbound_attack_type )
                raise

            response_content = self.get_response_content(app_response)
            status_code = getattr(app_response, 'status', 200)

        ####################################################
        # OUTBOUND
        ####################################################

        outbound_attack = self.check_outbound_attacks( response_content, request_path, source_ip, timestamp, status_code, inbound_attack_type )

        if outbound_attack:
            security_check = ATTACKS_CHECKS[outbound_attack['type']]
            self.handle_attack(outbound_attack, host, request_path, source_ip, timestamp, ja4h_fingerprint=ja4h_fingerprint)

        if inbound_attack and outbound_attack:
            attack = outbound_attack
        else:
            attack = inbound_attack or outbound_attack

        if security_check and self.SECURITY_CHECKS.get(security_check) == 3:
            log_only = True

        ####################################################
        # RESPONSE
        ####################################################

        # Already sent by the handler (prepare() called: WebSocket, SSE,
        # manual streaming): nothing can be replaced anymore, the attack
        # has been logged by handle_attack()
        if getattr(app_response, 'prepared', False):
            return app_response

        wrapped = AiohttpResponse(app_response) if app_response is not None else None

        response = self.process_response(wrapped, attack, log_only = log_only)

        # Back to the real aiohttp object: identity checks below
        # (response is http_exception) and aiohttp itself need it
        if isinstance(response, AiohttpResponse):
            response = response.response

        if response is None:
            # Nothing to send: neither an application nor a block response
            response = web.Response(status=500)

        if getattr(self, 'CHANGE_SERVER', False):
            self.change_server(response)

        # Pass-through of an HTTP exception: raise it again so aiohttp
        # (and outer middlewares) handle it as the application intended
        if http_exception is not None and response is http_exception:
            raise http_exception

        return response

    ####################################################
    # ROUTES
    ####################################################

    # Called by PyRASP.__init__(): routes are sent to the cloud server
    # at connection and returned by the get_routes() API
    def get_app_routes(self, app):

        app_routes = {}

        if not isinstance(app, web.Application):
            return app_routes

        routes = []
        self.collect_routes(app, '', routes)

        for route in routes:

            # Endpoint: route name when defined, otherwise its path.
            # A name reused by a sub-application for another path falls back to the path.
            endpoint = route['name'] or route['path']
            if endpoint in app_routes and app_routes[endpoint]['path'] != route['path']:
                endpoint = route['path']

            if endpoint not in app_routes:
                app_routes[endpoint] = { 'methods': [], 'path': route['path'] }

            for method in route['methods']:
                if method not in app_routes[endpoint]['methods']:
                    app_routes[endpoint]['methods'].append(method)

        return app_routes

    def collect_routes(self, app, prefix, routes):

        for resource in app.router.resources():

            # Sub-applications (add_subapp, add_domain)
            sub_app = getattr(resource, '_app', None)
            if sub_app is not None:
                sub_prefix = prefix + (getattr(resource, '_prefix', '') or '')
                self.collect_routes(sub_app, sub_prefix, routes)
                continue

            canonical = getattr(resource, 'canonical', None)
            if canonical is None:
                continue

            methods = []
            for route in resource:
                if route.method not in methods:
                    methods.append(route.method)

            routes.append({
                'name': resource.name,
                'path': prefix + canonical,
                'methods': methods
            })
            
    ####################################################
    # SECURITY FUNCTIONS
    ####################################################

    def check_route(self, request, request_method, request_path):

        attack = None
        route_exists = False

        # Routing is done before middlewares run: on a miss, match_info
        # carries the HTTPNotFound / HTTPMethodNotAllowed to be raised
        match_info = getattr(request, 'match_info', None)
        if match_info is not None and match_info.http_exception is None:
            route_exists = True

        if not route_exists:
            attack = {
                'type': ATTACK_PATH,
                'details': {
                    'location': 'request',
                    'payload': request_method + ' ' + request_path
                }
            }

        return attack

    ####################################################
    # RESPONSE PROCESSING
    ####################################################

    def build_block_response(self, status_code, content):

        if isinstance(content, str):
            content = content.encode('utf-8')

        return web.Response(
            body = content or b'',
            status = status_code,
            content_type = 'text/html',
            charset = 'utf-8'
        )

    def build_redirect_response(self, status_code, content):

        return web.Response(
            status = status_code,
            headers = {
                'Location': content,
                'Cache-Control': 'no-store, no-cache, must-revalidate',
                'Pragma': 'no-cache',
            },
            content_type = 'text/html',
            charset = 'utf-8'
        )

    def change_server(self, response):
        if response is not None and not getattr(response, 'prepared', False):
            # aiohttp only sets its own Server header if none is present
            response.headers['Server'] = getattr(self, 'SERVER_HEADER', 'Apache')
        return response

    ####################################################
    # REQUEST BODY
    ####################################################

    async def buffer_body(self, request):

        if self.BODY_KEY in request:
            return request[self.BODY_KEY]

        body = b''
        length = request.content_length

        # Chunked (no Content-Length) and oversized bodies are left untouched
        # so streaming uploads keep working
        if request.body_exists and length and length <= self.MAX_BODY_BUFFER:
            try:
                body = await request.content.readexactly(length)
            except asyncio.IncompleteReadError as exc:
                body = exc.partial
            self.replace_payload(request, body)

        request[self.BODY_KEY] = body

        return body

    def replace_payload(self, request, body):
        # The original stream is consumed: hand the handler a fresh one so
        # request.read(), .json(), .post(), .multipart() and .content all work.
        # The limit is sized to the body so feed_data() never pauses the
        # transport.
        reader = StreamReader(
            request.protocol,
            max(len(body), 2 ** 16),
            loop = asyncio.get_running_loop()
        )
        reader.feed_data(body)
        reader.feed_eof()
        request._payload = reader

    def get_body_data(self, request):
        return request.get(self.BODY_KEY, b'')

    ####################################################
    # UTILS
    ####################################################

    # Get request params
    def get_params(self, request):

        request_path = request.path
        request_method = request.method
        source_ip = self.get_ip(request)
        timestamp = time.time()
        host = request.host

        return (host, request_method, request_path, source_ip, timestamp)

    def get_request_path(self, request):

        path_elements = request.path.split('/') or []

        return path_elements

    def get_query_string(self, request):

        query_string = {}

        # Raw (still percent-encoded) form: request.query_string is already
        # decoded, which would turn %26 into a separator
        qs = request.rel_url.raw_query_string

        if qs:
            try:
                parsed = parse_qs(qs, keep_blank_values=True)
            except Exception:
                parsed = {}

            for name, values in parsed.items():
                query_string[self.to_text(name)] = [
                    self.to_text(value) for value in values
                ]

        return query_string

    def get_request_headers(self, request):

        headers = {}

        for name, value in request.headers.items():
            key = name.lower()
            value = self.to_text(value)
            headers[key] = f'{headers[key]}, {value}' if key in headers else value

        return headers

    def get_content_type(self, request):
        """Content-Type -> (mime_type, {parameters})"""

        raw = request.headers.get('Content-Type', '') or ''
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

    def get_posted_data(self, request):

        posted_data = {}

        mime_type, _ = self.get_content_type(request)

        # Form bodies only: a JSON body parsed by parse_qs would land the
        # whole payload in a variable NAME instead of a value
        if mime_type == self.FORM_TYPE:

            body = self.get_body_data(request)

            try:
                posted_data = parse_qs(
                    body.decode('utf-8', errors='ignore'),
                    keep_blank_values=True
                )
            except Exception:
                pass

        # Multipart text fields: same location as urlencoded variables
        elif mime_type == self.MULTIPART_TYPE:

            for name, value in self.get_multipart_parts(request, files=False):
                posted_data.setdefault(name, []).append(value)

        return posted_data

    def get_json_data(self, request):

        json_keys = []
        json_values = []

        mime_type, _ = self.get_content_type(request)

        if not (mime_type == 'application/json' or mime_type.endswith('+json')):
            return (json_keys, json_values)

        body = self.get_body_data(request)

        try:
            json_data = json.loads(body)
            (json_keys, json_values) = self.analyze_json(json_data)
        except Exception:
            pass

        return (json_keys, json_values)

    def get_multipart_parts(self, request, files = True):
        """
        Splits a multipart body.
        files=True  -> [ (filename, content_length), ... ] for file parts
        files=False -> [ (field_name, value), ... ] for text parts
        """

        parts = []

        mime_type, parameters = self.get_content_type(request)
        if mime_type != self.MULTIPART_TYPE:
            return parts

        boundary = parameters.get('boundary', '')
        if not boundary:
            return parts

        raw = self.get_body_data(request)
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

    def get_files(self, request):

        files = [[name, size] for name, size in self.get_multipart_parts(request)]

        return files

    def get_ip(self, request):
        if getattr(self, 'TRUST_PROXY_HEADERS', True):
            forwarded = request.headers.get('X-Forwarded-For')
            if forwarded:
                return forwarded.split(',')[0].strip()
        return request.remote or '0.0.0.0'

    # Process non-streamed response
    def get_response_content(self, response):

        # StreamResponse / FileResponse / WebSocketResponse: never buffered
        if not isinstance(response, web.Response):
            return None

        if response.prepared:
            return None

        content_type = (response.content_type or '').lower()

        if content_type.startswith(self.STREAMING_CONTENT_TYPES):
            return None

        if not any(content_type.startswith(t) for t in self.INSPECT_CONTENT_TYPES):
            return None

        # bytes for text=, body=bytes and json_response(); other payload
        # objects (files, async generators) are left alone
        body = response.body
        if not isinstance(body, (bytes, bytearray)):
            return None

        return self.decode_response_body(body, response.charset)

    # Encoding: aiohttp already hands out decoded str, no WSGI latin-1 dance
    def to_text(self, value):

        if value is None:
            return ''

        if isinstance(value, (bytes, bytearray)):
            try:
                return bytes(value).decode('utf-8')
            except UnicodeDecodeError:
                return bytes(value).decode('latin-1', errors='replace')

        return value if isinstance(value, str) else str(value)

    ####################################################
    # JA4H FINGERPRINTING
    ####################################################

    def get_ja4h_params(self, request):

        method = request.method
        version = f'HTTP/{request.version.major}.{request.version.minor}'
        headers = self.get_ja4h_headers_list(request)

        return (method, version, headers)

    def get_ja4h_headers_list(self, request):

        # raw_headers keeps the wire order, which JA4H depends on
        headers = []

        for name, value in request.raw_headers:
            headers.append([ self.to_text(name).lower(), self.to_text(value).lower() ])

        return headers

class AiohttpResponse:
    """
    Wraps an aiohttp response so it can go through process_response()
    like a framework response object: status_code maps to status,
    everything else is delegated.
    """

    def __init__(self, response):
        object.__setattr__(self, 'response', response)

    @property
    def status_code(self):
        return self.response.status

    @status_code.setter
    def status_code(self, value):
        self.response.set_status(value)

    def __getattr__(self, name):
        return getattr(self.response, name)

    def __setattr__(self, name, value):
        setattr(self.response, name, value)