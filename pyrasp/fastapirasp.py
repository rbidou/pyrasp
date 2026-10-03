import time

from urllib.parse import parse_qs
from fastapi import Request
from fastapi import Response as FastApiResponse
from fastapi.responses import RedirectResponse
from starlette.concurrency import iterate_in_threadpool
from starlette.routing import Match

try:
    from .pyrasp import PyRASP, DlpStreamScanner
    from .pyrasp_data import ATTACKS_CHECKS, ATTACK_PATH
except ImportError:
    from pyrasp.pyrasp import PyRASP, DlpStreamScanner
    from pyrasp.pyrasp_data import ATTACKS_CHECKS, ATTACK_PATH


class FastApiRASP(PyRASP):

    FORM_TYPE = 'application/x-www-form-urlencoded'
    MULTIPART_TYPE = 'multipart/form-data'
    POSTED_DATA_KEY = 'rasp_posted_data'
    FILES_KEY = 'rasp_files'

    def __init__(self, app = None, template = 'default', conf = None, params = {}, key = None, cloud_url = None):
        self.PLATFORM = 'FastAPI'

        # Init
        super().__init__(app, template, conf, params, key, cloud_url)

        """ Deprecated - seems to work without being replaced...
        if self.LOG_ENABLED:
            @app.on_event("shutdown")
            async def shutdown_event():
                if getattr(self, "BEACON", None):
                    global STOP_BEACON_THREAD
                    STOP_BEACON_THREAD = True

                if self.LOG_ENABLED:
                    self.LOG_QUEUE.put('--STOP--')
        """
                
    def register_security_checks(self, app):

        @app.middleware('http')
        async def security_checks_setup(request: Request, call_next):
    
            inbound_attack = None
            outbound_attack = None
            status_code = 200
            log_only = False
            security_check = None

            # Get Main params
            (host, request_method, request_path, source_ip, timestamp) = self.get_params(request)

            # Get posted data - need to do it here as async
            await self.load_posted_data(request)

            # Get vectors - need to do it here as async
            vectors = await self.get_vectors(request) 
            vectors = self.remove_exceptions(vectors) 

            # Ja4h fingerprint
            ja4h_fingerprint = self.calculate_ja4h_fingerprint(request) if (self.LOG_JA4H_FINGERPRINT or self.SECURITY_CHECKS.get('bots')) else None
            
            # Check inboud attacks
            inbound_attack = self.check_inbound_attacks(host, request_method, request_path, source_ip, timestamp, request, ja4h_fingerprint, vectors)
              
            # Send response
            if inbound_attack:
                security_check = ATTACKS_CHECKS[inbound_attack['type']]

            if not inbound_attack or self.SECURITY_CHECKS.get(security_check) == 3:
                response = await call_next(request)
            else:
                response = FastApiResponse()

            status_code = response.status_code
            inbound_attack_type = inbound_attack['type'] if inbound_attack else None
            
            # Check outbound attacks
            if inbound_attack or status_code >= 400:
                response_content = None
            
            else:
                response_content = await self.get_response_content(response, (host, request_path, source_ip, timestamp, ja4h_fingerprint))

            outbound_attack = self.check_outbound_attacks(response_content, request_path, source_ip, timestamp, status_code, inbound_attack_type)

            # Set response   
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

    ####################################################
    # RESPONSE BODY
    ####################################################

    # call_next() always returns a streaming response: buffer it only when
    # inspectable, otherwise scan its chunks as they are sent
    async def get_response_content(self, response, context):

        response_content = None
        content_type = response.headers.get('content-type')
        content_length = response.headers.get('content-length')
        content_encoding = response.headers.get('content-encoding')

        if self.should_inspect_response(content_type, content_length, content_encoding):
            chunks = [chunk async for chunk in response.body_iterator]
            response.body_iterator = iterate_in_threadpool(iter(chunks))
            response_content = self.decode_response_body(b''.join(chunks))

        elif content_length is None and self.should_scan_stream(content_type, content_encoding):
            response.body_iterator = self.scan_async_stream(response.body_iterator, DlpStreamScanner(self, context))

        return response_content

    ####################################################
    # ROUTES
    ####################################################
            
    def get_app_routes(self, app):

        app_routes = {}


        for route in app.routes:
            try:
                endpoint = route.name
                methods = list(route.methods)
                path = route.path
            except:
                pass
            else:
                app_routes[endpoint] = {
                    'methods': methods,
                    'path': path
                }

        return app_routes

    ####################################################
    # SECURITY CHECKS
    ####################################################

    # Check if a rule matches the request
    def check_route(self, request, request_method, request_path):

        attack = None
        route_exists = False

        for route in request.app.routes:
            match, _ = route.matches(request.scope)
            if match == Match.FULL:
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

        response = FastApiResponse(content = content, status_code= status_code)
        
        return response

    def build_redirect_response(self, status_code, content):
        
        return RedirectResponse(content, status_code=status_code) 

    ####################################################
    # PARAMS & VECTORS
    ####################################################
    
    # Get request params
    def get_params(self, request):
        request_path = request.url.path
        request_method = request.method
        source_ip_list = request.headers.get('x-forwarded-for') or request.client.host
        source_ip = source_ip_list.split(',')[0].strip()
        timestamp = time.time()
        host = request.headers.get('Host')
        return (host, request_method, request_path, source_ip, timestamp)
    
    def get_request_path(self, request):

        request_path = request.url.path
        path_elements = request_path.split('/') or []

        return path_elements
    
    def get_query_string(self, request):

        query_string = {}

        query_string_items = request.query_params.multi_items()

        for query_string_item in query_string_items:
            qs_variable = query_string_item[0]
            qs_value = query_string_item[1]

            if not qs_variable in query_string:
                query_string[qs_variable] = []

            query_string[qs_variable].append(qs_value)

        return query_string

    # Parse the body once and cache it: get_posted_data() is also called
    # synchronously by check_hpp()
    async def load_posted_data(self, request):

        posted_data = {}
        files = []

        mime_type = request.headers.get('content-type', '').split(';')[0].strip().lower()

        try:
            # Form bodies only: a JSON body parsed by parse_qs would land the
            # whole payload in a variable NAME instead of a value
            if mime_type == self.FORM_TYPE:
                body = await request.body()
                posted_data = parse_qs(body.decode('utf-8', errors='ignore'), keep_blank_values=True)

            # Multipart: text fields are posted data, files are kept for the upload check
            elif mime_type == self.MULTIPART_TYPE:
                await request.body()    # Cache the body so the route can parse it again
                form = await request.form()
                for name, value in form.multi_items():
                    if isinstance(value, str):
                        posted_data.setdefault(name, []).append(value)
                    # File input left empty by the user: no file sent
                    elif value.filename:
                        files.append([ value.filename, value.size or 0 ])
        except Exception:
            posted_data = {}
            files = []

        setattr(request.state, self.POSTED_DATA_KEY, posted_data)
        setattr(request.state, self.FILES_KEY, files)

    def get_posted_data(self, request):

        posted_data = getattr(request.state, self.POSTED_DATA_KEY, {})

        return posted_data    

    # Get multipart upload files: [ [ filename, size ], ... ]
    # Collected by load_posted_data(), as the form can only be parsed asynchronously
    def get_files(self, request):

        files = getattr(request.state, self.FILES_KEY, [])

        return files
    
    async def get_json_data(self, request):

        json_keys = []
        json_values = []

        try:
            json_data = await request.json()
            (json_keys, json_values) = self.analyze_json(json_data)
        except:
            json_keys = []
            json_values = []

        return (json_keys, json_values)
    
    def get_request_headers(self, request):

        return self.normalize_headers(request.headers.items())

    # Get request injection vectors
    async def get_vectors(self, request):

        vectors = {
            'path': [],
            'headers_names': [],
            'headers_values': [],
            'cookies': [],
            'user_agent': [],
            'referer': [],
            'qs_variables': [],
            'qs_values': [],
            'post_variables': [],
            'post_values': [],
            'json_keys': [],
            'json_values': [],
            
        }

        # Request path
        request_path_elements = self.get_request_path(request)
        for path_element in request_path_elements:
            if len(path_element):
                vectors['path'].extend(self.decode_value(path_element))

        query_string = self.get_query_string(request)
        for qs_variable in query_string:
            qs_values = query_string[qs_variable]
            vectors['qs_variables'].append(qs_variable)
            for qs_value in qs_values:
                if len(qs_value):
                    vectors['qs_values'].extend(self.decode_value(qs_value))

        # Posted data
        posted_data = self.get_posted_data(request)
        for post_variable in posted_data:
            post_values = posted_data[post_variable]
            vectors['post_variables'].append(post_variable)
            for post_value in post_values:
                if len(post_value):
                    vectors['post_values'].extend(self.decode_value(post_value))

        # JSON
        (json_keys, json_values) = await self.get_json_data(request)
        
        vectors['json_keys'] = json_keys

        for json_value in json_values:
            vectors['json_values'].extend(self.decode_value(json_value))    

        # Headers
        vectors.update(self.get_headers_vectors(self.get_request_headers(request)))

        # JSON in vectors
        (extracted_keys, extracted_values) = self.extract_json_vectors(vectors)

        vectors['json_keys'].extend(extracted_keys)
        vectors['json_values'].extend(extracted_values)

        return vectors

    ####################################################
    # JA4H FINGERPRINTING
    ####################################################

    def get_ja4h_params(self, request):

        scope = request.scope

        version = 'HTTP/' + str(scope.get('http_version') or '1.1')
        method = request.method

        raw_headers = [
        (
            name.decode('latin-1') if isinstance(name, bytes) else name,
            value.decode('latin-1') if isinstance(value, bytes) else value,
        )
        for name, value in request.headers.raw
    ]

        headers = [ [ name.lower(), value.lower() ] for name, value in raw_headers ]

        return (method, version, headers)
