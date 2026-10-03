import io
import json
import re
import time
from urllib.parse import parse_qs, unquote

from .pyrasp import PyRASP, DlpStreamScanner, ScannedStream, parse_content_disposition, recode_header_text

# DATA GLOBALS
try:
    from .pyrasp_data import ATTACKS_CHECKS
except:
    from pyrasp.pyrasp_data import ATTACKS_CHECKS

class WsgiRASP(PyRASP):

    FORM_TYPE = 'application/x-www-form-urlencoded'
    MULTIPART_TYPE = 'multipart/form-data'
    BODY_KEY = 'pyrasp.body'

    def __init__(self, app = None, template = 'default', conf = None, params = {}, key = None, cloud_url = None):
        self.PLATFORM = 'WSGI'
        super().__init__(app, template, conf, params, key, cloud_url)        

    def __call__(self, environ, start_response):

        process_outbound = True
        inbound_attack_type = None
        log_only = False
        security_check = None

        capture = {
            'status_line': '200 OK',
            'status': 200,
            'headers': [],
            'exc_info': None
        }

        deferred = {'called': False}

        def rasp_start_response(status, headers, exc_info=None):
            # Held back: the response may still be blocked by an outbound check
            capture['status_line'] = status
            capture['status'] = self.get_status_code(status)
            capture['headers'] = list(headers)
            capture['exc_info'] = exc_info
            deferred['called'] = True
            return lambda data: None        # legacy write() not supported

        # Main params
        (host, request_method, request_path, source_ip, timestamp) = self.get_params(environ)

        # JA4H fingerprint
        ja4h_fingerprint = None
        if self.LOG_JA4H_FINGERPRINT or self.SECURITY_CHECKS.get('bots'):
            ja4h_fingerprint = self.calculate_ja4h_fingerprint(environ)

        ####################################################
        # INBOUND
        ####################################################

        inbound_attack = self.check_inbound_attacks( host, request_method, request_path, source_ip, timestamp, environ, ja4h_fingerprint=ja4h_fingerprint )

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
        response_content = None
        status_code = 200

        if process_outbound:

            try:
                app_response = self.wsgi_app(environ, rasp_start_response)
            except Exception:
                self.check_outbound_attacks( None, request_path, source_ip, timestamp, 500, inbound_attack_type )
                raise

            context = (host, request_path, source_ip, timestamp, ja4h_fingerprint)
            response_content, app_response = self.get_response_content( app_response, capture['headers'], environ, context )

            status_code = capture['status']

            app_response = WsgiResponse( app_response, capture['status_line'], capture['headers'] )

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

        response = self.process_response(app_response, attack, log_only = log_only)

        if app_response is not None and response is not app_response:
            self.close_iterable(app_response)

        # Block or redirect: the builder carried status and headers back up
        if isinstance(response, WsgiResponse):
            if app_response is not None and app_response is not response:
                self.close_iterable(app_response)
            start_response(response.status_line, list(response.headers))
            return response

        # Pass-through
        if not deferred['called']:
            # The wrapped app never called start_response, or was never called
            self.close_iterable(response)
            body = b''
            start_response('500 Internal Server Error', [
                ('Content-Type', 'text/plain'),
                ('Content-Length', '0'),
            ])
            return [body]

        headers = capture['headers']
        if getattr(self, 'CHANGE_SERVER', False):
            headers = [(n, v) for n, v in headers if n.lower() != 'server']
            headers.append(('Server', getattr(self, 'SERVER_HEADER', 'Apache')))

        start_response(capture['status_line'], headers, capture['exc_info'])

        return response
    
    def register_security_checks(self, app):
        if not callable(app):
            raise TypeError('WsgiRASP must wrap a WSGI callable (app.wsgi_app)')
        self.wsgi_app = app

    ####################################################
    # ROUTES
    ####################################################

    # Not supported at WSGI level
    def get_app_routes(self, app):
        return {}

    ####################################################
    # SECURITY FUNCTIONS
    ####################################################

    # Not supported at WSGI level
    def check_route(self, request, request_method, request_path):
        return None

    ####################################################
    # RESPONSE PROCESSING
    ####################################################

    def build_block_response(self, status_code, content):

        if isinstance(content, str):
            content = content.encode('utf-8')

        headers = [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Content-Length', str(len(content))),
        ]

        '''
        if getattr(self, 'CHANGE_SERVER', False):
            headers.append(('Server', getattr(self, 'SERVER_HEADER', 'Apache')))
        '''

        return WsgiResponse(content, self.status_line(status_code), headers)

    def build_redirect_response(self, status_code, content):

        body = b''

        headers = [
            ('Location', content),
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Content-Length', '0'),
            ('Cache-Control', 'no-store, no-cache, must-revalidate'),
            ('Pragma', 'no-cache'),
        ]

        '''
        if getattr(self, 'CHANGE_SERVER', False):
            headers.append(('Server', getattr(self, 'SERVER_HEADER', 'Apache')))
        '''

        return WsgiResponse(body, self.status_line(status_code), headers)

    def status_line(self, status_code):
        from http import HTTPStatus
        try:
            return f'{status_code} {HTTPStatus(status_code).phrase}'
        except ValueError:
            return f'{status_code} '

    def get_status_code(self, status):
        """WSGI status line ('403 Forbidden') -> int"""
        try:
            return int(str(status).split(' ', 1)[0])
        except (ValueError, AttributeError):
            return 500

    def change_server(self, response):
        if response is not None:
            response.headers['Server'] = self.SERVER_HEADER
        return response

    ####################################################
    # UTILS
    ####################################################
    
    # Get request params
    def get_params(self, environ):

        request_path = environ.get('PATH_INFO')
        request_method = environ.get('REQUEST_METHOD')
        source_ip = self.get_ip(environ)
        timestamp = time.time()
        host = environ.get('HTTP_HOST')

        return (host, request_method, request_path, source_ip, timestamp)

    def get_request_path(self, environ):
    
        request_path = environ.get('PATH_INFO')
        path_elements = request_path.split('/') or []

        return path_elements
    
    def get_query_string(self, environ):

        query_string = {}

        qs = environ.get('QUERY_STRING', '')

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
        
    def get_request_headers(self, environ):
    
            headers = {}
            
            for key, value in environ.items():
                if key.startswith('HTTP_'):
                    header_name = self.header_name(key[5:])
                elif key in ('CONTENT_TYPE', 'CONTENT_LENGTH') and value:
                    header_name = self.header_name(key)
                else:
                    continue
                headers[header_name] = self.to_text(value)
    
            return headers
    
    def get_body_data(self, environ):

        if self.BODY_KEY in environ:
            return environ[self.BODY_KEY]

        body = b''

        try:
            length = int(environ.get('CONTENT_LENGTH') or 0)
        except (TypeError, ValueError):
            length = 0

        stream = environ.get('wsgi.input')

        if stream is not None:
            try:
                body = stream.read(length)
            except Exception:
                body = b''
            environ['wsgi.input'] = io.BytesIO(body)
            environ['wsgi.input_terminated'] = True

        environ[self.BODY_KEY] = body
            
        return body

    def get_content_type(self, environ):
        """CONTENT_TYPE -> (mime_type, {parameters})"""

        raw = environ.get('CONTENT_TYPE', '') or ''
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

    def get_posted_data(self, environ):

        posted_data = {}

        mime_type, _ = self.get_content_type(environ)

        # Form bodies only: a JSON body parsed by parse_qs would land the
        # whole payload in a variable NAME instead of a value
        if mime_type == self.FORM_TYPE:

            body = self.get_body_data(environ)

            try:
                posted_data = parse_qs(
                    body.decode('utf-8', errors='ignore'),
                    keep_blank_values=True
                )
            except Exception:
                pass

        # Multipart text fields: same location as urlencoded variables
        elif mime_type == self.MULTIPART_TYPE:

            for name, value in self.get_multipart_parts(environ, files=False):
                posted_data.setdefault(name, []).append(value)

        return posted_data

    def get_json_data(self, environ):

        json_keys = []
        json_values = []

        mime_type, _ = self.get_content_type(environ)

        if not (mime_type == 'application/json' or mime_type.endswith('+json')):
            return (json_keys, json_values)

        body = self.get_body_data(environ)

        try:
            json_data = json.loads(body)
            (json_keys, json_values) = self.analyze_json(json_data)
        except Exception:
            pass

        return (json_keys, json_values)

    def get_multipart_parts(self, environ, files = True):
        """
        Splits a multipart body.
        files=True  -> [ (filename, content_length), ... ] for file parts
        files=False -> [ (field_name, value), ... ] for text parts
        """

        parts = []

        mime_type, parameters = self.get_content_type(environ)
        if mime_type != self.MULTIPART_TYPE:
            return parts

        boundary = parameters.get('boundary', '')
        if not boundary:
            return parts

        raw = self.get_body_data(environ)
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

    def get_files(self, environ):

        files = [[name, size] for name, size in self.get_multipart_parts(environ)]

        return files

    def get_ip(self, environ):
        if getattr(self, 'TRUST_PROXY_HEADERS', True):
            forwarded = environ.get('HTTP_X_FORWARDED_FOR')
            if forwarded:
                return forwarded.split(',')[0].strip()
        return environ.get('REMOTE_ADDR', '0.0.0.0')

    def header_name(self, key):
        return '-'.join(part.lower() for part in key.split('_'))

    # Process non-streamed response
    def get_response_content(self, result, headers, environ = None, context = None):

        if result is None:
            return None, result

        # Server-optimized file transfer: never buffer
        file_wrapper = environ.get('wsgi.file_wrapper') if environ else None
        if file_wrapper is not None:
            try:
                if isinstance(result, file_wrapper):
                    return None, result
            except TypeError:
                pass

        content_type = ''
        content_length = None
        content_encoding = None

        for name, value in headers:
            lowered = name.lower()
            if lowered == 'content-type':
                content_type = value.lower()
            elif lowered == 'content-encoding':
                content_encoding = value
            elif lowered == 'content-length':
                try:
                    content_length = int(value)
                except (TypeError, ValueError):
                    content_length = None

        if content_type.startswith(self.STREAMING_CONTENT_TYPES):
            return None, self.scan_stream(result, content_type, content_encoding, context)

        if not any(content_type.startswith(t) for t in self.INSPECT_CONTENT_TYPES):
            return None, result

        # No Content-Length means a streamed or chunked response: consuming
        # it would break SSE and long-lived responses. A plain list/tuple is
        # already materialized, so its absence is harmless there.
        if content_length is None and not isinstance(result, (list, tuple)):
            return None, self.scan_stream(result, content_type, content_encoding, context)

        if content_length is not None and content_length > self.MAX_BODY_INSPECT:
            return None, result

        chunks = []
        try:
            for chunk in result:
                chunks.append(chunk if isinstance(chunk, bytes) else bytes(chunk))
        except Exception:
            # Partially consumed: return what was read rather than a body
            # the client would never receive
            return None, [b''.join(chunks)]

        body = b''.join(chunks)

        # The original iterable was consumed: close it (Werkzeug teardown
        # callbacks run here), return a fresh body
        self.close_iterable(result)

        return self.decode_response_body(body), [body]

    # Streamed body: never buffered, scanned chunk by chunk when it is text
    def scan_stream(self, result, content_type, content_encoding, context):

        stream = result

        if context is not None and self.should_scan_stream(content_type, content_encoding):
            stream = ScannedStream(result, DlpStreamScanner(self, context))

        return stream

    # WSGI stuff
    def close_iterable(self, result):
        # WSGI contract: an iterable providing close() must get it called
        if hasattr(result, 'close'):
            try:
                result.close()
            except Exception:
                pass

    # Encoding
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

        return recode_header_text(value)

    ####################################################
    # JA4H FINGERPRINTING
    ####################################################

    def get_ja4h_params(self, environ):

        method = environ.get('REQUEST_METHOD')
        version = environ.get('SERVER_PROTOCOL', '')
        headers = self.get_ja4h_headers_list(environ)

        return (method, version, headers)

    def get_ja4h_headers_list(self, environ):

        headers = []

        for key, value in environ.items():
            if key.startswith('HTTP_'):
                headers.append( [ self.header_name(key[5:]), value.lower()])
            elif key in ('CONTENT_TYPE', 'CONTENT_LENGTH') and value:
                headers.append( [ self.header_name(key), value.lower()])

        return headers

class WsgiHeaders(list):
    """
    WSGI headers: a list of (name, value) tuples, with dict-style access
    so change_server() and friends work unchanged.
    """

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

class WsgiResponse:
    """
    WSGI body iterable exposing status_code / headers, so it can go through
    process_response() like a framework response object.
    """

    def __init__(self, body, status_line, headers):

        if body is None:
            self.body = []
        elif isinstance(body, (bytes, bytearray)):
            self.body = [bytes(body)]
        else:
            self.body = body                 # list, ClosingIterator, generator

        self.status_line = status_line
        self.headers = WsgiHeaders(headers)
        self.status_code = self.parse_status(status_line)

    def parse_status(self, status_line):
        try:
            return int(str(status_line).split(' ', 1)[0])
        except Exception:
            return 500

    # WSGI contract
    def __iter__(self):
        return iter(self.body)

    def close(self):
        # ClosingIterator.close() runs Werkzeug's teardown callbacks
        if hasattr(self.body, 'close'):
            try:
                self.body.close()
            except Exception:
                pass