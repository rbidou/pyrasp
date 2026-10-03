import time
from functools import wraps
from urllib.parse import parse_qs, urlsplit

import azure.functions as func

try:
    from .pyrasp import PyRASP, make_security_log, send_log
    from .pyrasp_data import ATTACKS_CHECKS, JA4H_AZURE_PLATFORM_HEADERS
except ImportError:
    from pyrasp.pyrasp import PyRASP, make_security_log, send_log
    from pyrasp.pyrasp_data import ATTACKS_CHECKS, JA4H_AZURE_PLATFORM_HEADERS


class AzureRASP(PyRASP):

    def __init__(self, app = None, template = 'default', conf = None, params = {}, key = None, cloud_url = None):
        self.PLATFORM = 'Azure Function'
        super().__init__(app, template, conf, params, key, cloud_url)

    ####################################################
    # CHECKS CONTROL
    ####################################################

    # Azure Function handler wrapper
    def register(self, f):
    
        @wraps(f)
        def decorator(req):

            request = req

            # Sending beacons to get configuration and blacklist updates
            self.beacon_if_due()

            (host, request_method, request_path, source_ip, timestamp) = self.get_params(request)

            # Ja4h fingerprint
            ja4h_fingerprint = self.calculate_ja4h_fingerprint(request) if self.LOG_JA4H_FINGERPRINT or self.SECURITY_CHECKS.get('bots') else None

            # Analyze request
            inbound_attack = None
            outbound_attack = None
            log_only = False
            security_check = None
            status_code = 200
            response = func.HttpResponse()

            inbound_attack = self.check_inbound_attacks(host, request_method, request_path, source_ip, timestamp, request, ja4h_fingerprint)

            if inbound_attack:
                security_check = ATTACKS_CHECKS[inbound_attack['type']]

            if any([
                inbound_attack is None,
                not security_check is None and self.SECURITY_CHECKS.get(security_check) == 3
            ]):
                response = f(req)

            response_content = self.get_response_content(response)
            status_code = response.status_code
            inbound_attack_type = inbound_attack['type'] if inbound_attack else None

            # Analyze response
            outbound_attack = self.check_outbound_attacks(response_content, request_path, source_ip, timestamp, status_code, inbound_attack_type)

            if outbound_attack:
                security_check = ATTACKS_CHECKS[outbound_attack['type']]

            if outbound_attack:
                self.handle_attack(outbound_attack, host, request_path, source_ip, timestamp, ja4h_fingerprint=ja4h_fingerprint)
            elif inbound_attack:
                self.handle_attack(inbound_attack, host, request_path, source_ip, timestamp, ja4h_fingerprint=ja4h_fingerprint)

            # Check log only
            if security_check and self.SECURITY_CHECKS.get(security_check) == 3:
                log_only = True

            response = self.process_response(response, inbound_attack or outbound_attack, log_only = log_only)
                
            return response
            
        return decorator

    # Inspectable text body, None otherwise (binary, too large...)
    def get_response_content(self, response):

        response_content = None
        body = response.get_body() or b''

        if self.should_inspect_response(response.mimetype, len(body), response.headers.get('Content-Encoding')):
            response_content = self.decode_response_body(body, response.charset)

        return response_content

    ####################################################
    # RESPONSE PROCESSING
    ####################################################

    # Alter response
    def process_response(self, response, attack = None, log_only = True):

        status_code = response.status_code

        if attack:
            if not log_only:
                response = self.make_attack_response(attack)
            self.REQUESTS['attacks'] += 1

        elif status_code == 200:
            self.REQUESTS['success'] += 1

        else:
            self.REQUESTS['errors'] += 1

        return response
    
    def build_block_response(self, status_code, content):

        response = func.HttpResponse(content, status_code=status_code)

        return response
    
    def build_redirect_response(self, status_code, content):

        return func.HttpResponse(content,headers={'Location': content},status_code=status_code)
    
    ####################################################
    # PARAMS & VECTORS
    ####################################################

    def get_params(self, request):

        (host, request_method, request_path, source_ip, timestamp) = ('', '', '', '', time.time())


        headers = dict(request.headers)

        host = headers.get('host') if headers.get('host') else '127.0.0.1'
        request_method = str(request.method)
        request_path = headers.get('x-original-url') if headers.get('x-original-url') else '/'

        source_ip_port = headers.get('x-forwarded-for')
        source_ip = source_ip_port.split(':')[0] if source_ip_port else '127.0.0.1'

        return (host, request_method, request_path, source_ip, timestamp)
    
    # Parsed from the raw URL: request.params keeps a single value per variable (HPP)
    def get_query_string(self, request):

        query_string = parse_qs(urlsplit(request.url).query, keep_blank_values=True)

        return query_string

    def get_posted_data(self, request):

        posted_data = {}

        content_type = (request.headers.get('content-type') or '').split(';')[0].strip().lower()

        # Multipart and JSON bodies are analyzed by get_files and get_json_data
        if content_type != 'multipart/form-data' and 'json' not in content_type:
            body = request.get_body().decode('utf-8', errors='replace')
            posted_data = parse_qs(body, keep_blank_values=True)

        return posted_data
    
    def get_request_path(self, request):

        headers = dict(request.headers)

        request_path = headers.get('x-original-url') if headers.get('x-original-url') else '/'

        return request_path.split('/')
    
    def get_json_data(self, request):

        json_keys = []
        json_values = []

        try:
            json_data = request.get_json()
            (json_keys, json_values) = self.analyze_json(json_data)
        except:
            pass

        return (json_keys, json_values)
    
    def get_request_headers(self, request):

        headers = dict(request.headers)

        return headers

    def get_files(self, request):

        files_list = []

        headers = dict(request.headers)
        content_type = headers.get('content-type') or headers.get('Content-Type') or ''
        if content_type.split(';')[0].strip().lower() != 'multipart/form-data':
            return files_list

        try:
            files = request.files
        except Exception:
            # Malformed multipart body: nothing that can be validated
            return files_list

        for field_name in files:
            for uploaded_file in files.getlist(field_name):

                # File input left empty by the user: no file sent
                if not uploaded_file.filename:
                    continue

                # Size measured on the in-memory stream, without copying the content,
                # then the position is restored so the function can still read the file
                stream = uploaded_file.stream
                position = stream.tell()
                stream.seek(0, 2)
                size = stream.tell()
                stream.seek(position)

                files_list.append([ uploaded_file.filename, size ])

        return files_list

    ####################################################
    # LOGGING
    ####################################################

    def log_security_event(self, event_type, source_ip, user = None, details = {}):

        log_data = make_security_log(self.APP_NAME, event_type, source_ip, self.LOG_FORMAT, user, details, False)

        try:
            send_log(log_data, self.LOG_SERVER, self.LOG_PORT, self.LOG_PROTOCOL, self.LOG_PATH)
        except Exception as e:
            self.print_screen(f'[PyRASP] Error sending logs : {str(e)}', level = 100)

    ####################################################
    # JA4H FINGERPRINTING
    ####################################################

    def get_ja4h_params(self, request):

        method = getattr(request, 'method', 'GET')

        # The HTTP version used by the client is not available to the function
        version = 'HTTP/1.1'

        request_headers = getattr(request, 'headers', None) or {}

        # Headers added by the Azure front end are not sent by the client:
        # they are removed so that the fingerprint describes the client only
        raw_headers = self._ja4h_strip_azure_headers(list(request_headers.items()))

        headers = [ [ name.lower(), value.lower() ] for name, value in raw_headers ]

        return (method, version, headers)

    @staticmethod
    def _ja4h_strip_azure_headers(raw_headers):

        exact = JA4H_AZURE_PLATFORM_HEADERS['exact']
        prefixes = JA4H_AZURE_PLATFORM_HEADERS['prefixes']

        headers = []

        for name, value in raw_headers:

            lowered = name.lower()

            if lowered in exact or lowered.startswith(prefixes):
                continue

            headers.append((name, value))

        return headers