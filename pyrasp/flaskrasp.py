import signal
import time
from functools import partial

from flask import g, request
from flask import redirect as flask_redirect
from flask import Response as FlaskResponse

try:
    from .pyrasp import PyRASP, DlpStreamScanner, ScannedStream, handle_kb_interrupt
    from .pyrasp_data import ATTACKS_CHECKS, ATTACK_PATH
except ImportError:
    from pyrasp.pyrasp import PyRASP, DlpStreamScanner, ScannedStream, handle_kb_interrupt
    from pyrasp.pyrasp_data import ATTACKS_CHECKS, ATTACK_PATH


class FlaskRASP(PyRASP):

    def __init__(self, app = None, template = 'default', conf = None, params = {}, key = None, cloud_url = None):
        self.PLATFORM = 'Flask'
        super().__init__(app, template, conf, params, key, cloud_url)

        if self.LOG_ENABLED or self.BEACON:
            signal.signal(signal.SIGINT, partial(handle_kb_interrupt, self))

            
    ####################################################
    # ROUTES
    ####################################################
            
    def get_app_routes(self, app):

        app_routes = {}

        for rule in app.url_map.iter_rules():

            methods = list(rule.methods)
            endpoint = str(rule.endpoint)
            path = str(rule)
            app_routes[endpoint] = { 
                'methods': methods,
                'path': path
            }

        return app_routes
    
    ####################################################
    # SECURITY CHECKS
    ####################################################

    # Register
    def register_security_checks(self, app):
        self.set_before_security_checks(app)
        self.set_after_security_checks(app)

    # Incoming request
    def set_before_security_checks(self, app):

        @app.before_request
        def before_request_callback():

            (host, request_method, request_path, source_ip, timestamp) = self.get_params(request)

            if self.LOG_JA4H_FINGERPRINT or self.SECURITY_CHECKS.get('bots'):
                ja4h_fingerprint = self.calculate_ja4h_fingerprint(request)
            else :
                ja4h_fingerprint = None

            setattr(g, 'ja4h_fingerprint', ja4h_fingerprint)
            
            attack = self.check_inbound_attacks(host, request_method, request_path, source_ip, timestamp, request, ja4h_fingerprint)

            # Pass attack to @after_request (logging, response): request stopped unless check is Log Only
            if not attack == None:
                setattr(g, 'attack', attack)
                security_check = ATTACKS_CHECKS[attack['type']]
                if not self.SECURITY_CHECKS.get(security_check) == 3:
                    return FlaskResponse()
        
    # Outgoing responses
    def set_after_security_checks(self, app):
        @app.after_request
        def after_request_callback(response):

            (host, request_method, request_path, source_ip, timestamp) = self.get_params(request)

            status_code = 200
            response_attack = None
            request_attack = None
            log_only = False
            security_check = None
            inbound_attack_type = None

            # Get attack from @before_request checks
            current_attack = getattr(g, 'attack', None)
            
            if current_attack is not None:
                request_attack = current_attack

            status_code = response.status_code
            inbound_attack_type = current_attack['type'] if current_attack else None

            # Check brute force, flood and data leaks
            context = (host, request_path, source_ip, timestamp, getattr(g, 'ja4h_fingerprint', None))
            response_content = self.get_response_content(response, context)
            response_attack = self.check_outbound_attacks(response_content, request_path, source_ip, timestamp, status_code, inbound_attack_type)

            # Set response   
            if response_attack:
                security_check = ATTACKS_CHECKS[response_attack['type']]
            elif request_attack:
                security_check = ATTACKS_CHECKS[request_attack['type']]
            
            if response_attack:
                self.handle_attack(response_attack, host, request_path, source_ip, timestamp, ja4h_fingerprint=getattr(g, 'ja4h_fingerprint', None))
            elif request_attack:
                self.handle_attack(request_attack, host, request_path, source_ip, timestamp, ja4h_fingerprint=getattr(g, 'ja4h_fingerprint', None))

            # Check log only
            if security_check and self.SECURITY_CHECKS.get(security_check) == 3:
                log_only = True

            # Process response
            response = self.process_response(response, response_attack or request_attack, log_only = log_only)

            return response

    # Buffered response: inspected as a whole. Streamed response (generator):
    # never buffered, its chunks are scanned as they are sent
    def get_response_content(self, response, context):

        response_content = None
        content_type = response.headers.get('Content-Type')
        content_encoding = response.headers.get('Content-Encoding')

        # File transfers (send_file) are left alone
        if response.direct_passthrough:
            pass

        elif response.is_streamed:
            if self.should_scan_stream(content_type, content_encoding):
                response.response = ScannedStream(response.iter_encoded(), DlpStreamScanner(self, context))

        else:
            content_length = response.content_length
            if content_length is None:
                content_length = response.calculate_content_length()
            if self.should_inspect_response(content_type, content_length, content_encoding):
                response_content = self.decode_response_body(response.get_data(), response.mimetype_params.get('charset'))

        return response_content

    ####################################################
    # SECURITY FUNCTIONS
    ####################################################

    # Check if a route matches the request
    def check_route(self, request, request_method, request_path):

        attack = None
        route_exists = False

        route = request.url_rule
        if route:
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

        response = FlaskResponse()
        response.set_data(content)
        response.status_code = status_code

        return response
    
    def build_redirect_response(self, status_code, content):
        
        return flask_redirect(content,code=status_code)

    ####################################################
    # PARAMS & VECTORS
    ####################################################
    
    # Get request params
    def get_params(self, request):
        request_path = request.path
        request_method = request.method
        source_ip_list = request.environ.get('HTTP_X_FORWARDED_FOR') or request.environ.get('REMOTE_ADDR')
        source_ip = source_ip_list.split(',')[0].strip()
        timestamp = time.time()
        host = request.host
        return (host, request_method, request_path, source_ip, timestamp)
    
    def get_request_path(self, request):

        request_path = request.path
        path_elements = request_path.split('/') or []

        return path_elements
    
    def get_query_string(self, request):

        query_string = {}

        query_string_objects = request.args

        for qs_variable in query_string_objects.keys():
            qs_values = query_string_objects.getlist(qs_variable)
            query_string[qs_variable] = qs_values
        
        return query_string
    
    def get_posted_data(self, request):

        posted_data = request.form.to_dict(flat=False)

        return posted_data

    def get_json_data(self, request):

        json_keys = []
        json_values = []

        try:
            json_data = request.get_json(force=True)
            (json_keys, json_values) = self.analyze_json(json_data)
        except Exception as e:
            pass

        return (json_keys, json_values)
    
    def get_request_headers(self, request):

        return self.normalize_headers(request.headers.items())

    # Get multipart upload files: [ [ filename, size ], ... ]
    def get_files(self, request):

        files_list = []

        for field_name in request.files:
            for uploaded_file in request.files.getlist(field_name):

                # File input left empty by the user: no file sent
                if not uploaded_file.filename:
                    continue

                # Size measured without reading the content, position restored
                # so that the application reads the complete file
                stream = uploaded_file.stream
                position = stream.tell()
                stream.seek(0, 2)
                size = stream.tell()
                stream.seek(position)

                files_list.append([ uploaded_file.filename, size ])

        return files_list

    ####################################################
    # JA4H FINGERPRINTING
    ####################################################

    def get_ja4h_params(self, request):

        version = request.environ.get('SERVER_PROTOCOL', 'HTTP/1.1')
        method = request.method
        headers = [ [ name.lower(), value.lower() ] for name, value in list(request.headers.items()) ]

        return (method, version, headers)
