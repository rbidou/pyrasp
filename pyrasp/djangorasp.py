import time
import json

from django.conf import settings as django_settings
from django.http import HttpResponse
from django.http.multipartparser import MultiPartParser
from django.shortcuts import redirect as django_redirect
from django.urls import URLPattern, get_resolver, resolve
from django.utils.datastructures import ImmutableList

try:
    from .pyrasp import PyRASP, DlpStreamScanner, ScannedStream
    from .pyrasp_data import ATTACKS_CHECKS, ATTACK_PATH
except ImportError:
    from pyrasp.pyrasp import PyRASP, DlpStreamScanner, ScannedStream
    from pyrasp.pyrasp_data import ATTACKS_CHECKS, ATTACK_PATH


class RawFileNamesParser(MultiPartParser):

    """
    Django strips paths from uploaded file names ('../../etc/passwd' -> 'passwd')
    and drops the files named '', '.' or '..': the upload check would never see
    them. Every declared file name is recorded as [ raw_name, sanitized_name ].
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.raw_file_names = []

    def sanitize_file_name(self, file_name):
        sanitized_name = super().sanitize_file_name(file_name)
        self.raw_file_names.append([ file_name, sanitized_name ])
        return sanitized_name


class DjangoRASP(PyRASP):

    RAW_FILE_NAMES_KEY = 'pyrasp_raw_file_names'

    def __init__(self, get_response):

        self.PLATFORM = 'Django'
        self.get_response = get_response

        try:
            template = django_settings.PYRASP_TEMPLATE or 'default'
        except:
            template = 'default'

        try:
            conf = django_settings.PYRASP_CONF or None
        except:
            conf = None

        try:
            key = django_settings.PYRASP_KEY or None
        except:
            key = None

        try:
            cloud_url = django_settings.PYRASP_CLOUD_URL or None
        except:
            cloud_url = None

        try:
            params = django_settings.PYRASP_PARAMS or {}
        except:
            params = {}

        # Init
        super().__init__(None, template, conf, params, key, cloud_url)

    def __call__(self, request):

        inbound_attack = None
        outbound_attack = None
        error = False
        status_code = 200
        log_only = False
        security_check = None

        # Get Main params
        (host, request_method, request_path, source_ip, timestamp) = self.get_params(request)

        # Keep raw upload file names: must be set before the body is parsed
        self.set_multipart_parser(request)

        # Ja4h fingerprint
        ja4h_fingerprint = self.calculate_ja4h_fingerprint(request) if self.LOG_JA4H_FINGERPRINT or self.SECURITY_CHECKS.get('bots') else None

        # Check inboud attacks
        inbound_attack = self.check_inbound_attacks(host, request_method, request_path, source_ip, timestamp, request, ja4h_fingerprint)

        if inbound_attack:
            security_check = ATTACKS_CHECKS[inbound_attack['type']]

        if not inbound_attack or self.SECURITY_CHECKS.get(security_check) == 3:
            response = self.get_response(request)
        else:
            response = HttpResponse()

        status_code = response.status_code
        inbound_attack_type = inbound_attack['type'] if inbound_attack else None

        # Check outbound attacks
        if inbound_attack or status_code >= 400:
            response_content = None

        else:
            response_content = self.get_response_content(response, (host, request_path, source_ip, timestamp, ja4h_fingerprint))

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

    ####################################################
    # RESPONSE BODY
    ####################################################

    # Buffered response: inspected as a whole. Streamed response (no .content):
    # its chunks are scanned as they are sent
    def get_response_content(self, response, context):

        response_content = None
        content_type = response.get('Content-Type')
        content_encoding = response.get('Content-Encoding')

        if getattr(response, 'streaming', False):
            if self.should_scan_stream(content_type, content_encoding):
                scanner = DlpStreamScanner(self, context)
                if getattr(response, 'is_async', False):
                    response.streaming_content = self.scan_async_stream(response.streaming_content, scanner)
                else:
                    response.streaming_content = ScannedStream(response.streaming_content, scanner)

        elif self.should_inspect_response(content_type, len(response.content), content_encoding):
            response_content = self.decode_response_body(response.content, response.charset)

        return response_content

    ####################################################
    # ROUTES
    ####################################################
            
    def get_app_routes(self, app):

        app_routes = {}

        count = 0

        for url_pattern in get_resolver().url_patterns:

            if not isinstance(url_pattern, URLPattern):
                continue

            methods = []
            path = str(url_pattern.pattern)
            endpoint = str(url_pattern.lookup_str)

            app_routes[endpoint] = { 
                'methods': methods,
                'path': path
            }

            count += 1

        return app_routes

    ####################################################
    # SECURITY FUNCTIONS
    ####################################################

    def check_route(self, request, request_method, request_path):

        attack = None
        route_exists = True

        try:
            resolve(request_path)
        except Exception as e:
            route_exists = False

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

        response = HttpResponse()
        response.content = content
        response.status_code = status_code

        return response
    
    def build_redirect_response(self, status_code, content):
        
        return django_redirect(content)


    ####################################################
    # UTILS
    ####################################################
    
    # Get request params
    def get_params(self, request):

        request_path = request.path
        request_method = request.method
        source_ip_list = request.headers.get('X-Forwarded-For') or request.META.get('REMOTE_ADDR')
        source_ip = source_ip_list.split(',')[0].strip()
        timestamp = time.time()
        host = request.headers.get('Host')

        return (host, request_method, request_path, source_ip, timestamp)
    
    def get_request_path(self, request):

        request_path = request.path
        path_elements = request_path.split('/') or []

        return path_elements
    
    def get_query_string(self, request):

        query_string = {}

        query_string_item = request.GET or {}

        for qs_variable in query_string_item:
            query_string[qs_variable] = query_string_item.getlist(qs_variable)
        
        return query_string
    
    def get_posted_data(self, request):

        posted_data = {}

        posted_data_item = request.POST or {}

        for post_variable in posted_data_item:
            posted_data[post_variable] = posted_data_item.getlist(post_variable)

        return posted_data

    def get_json_data(self, request):

        json_keys = []
        json_values = []

        # Form and multipart bodies are inspected by get_posted_data().
        # request.body cannot be read once Django has parsed a multipart body
        # (RawPostDataException), so those content types are skipped.
        content_type = (request.content_type or '').lower()
        if content_type in ('application/x-www-form-urlencoded', 'multipart/form-data'):
            return (json_keys, json_values)

        try:
            json_data = json.loads(request.body)
        except Exception:
            # Empty or non-JSON body, undecodable bytes,
            # or body larger than DATA_UPLOAD_MAX_MEMORY_SIZE (RequestDataTooBig)
            return (json_keys, json_values)

        (json_keys, json_values) = self.analyze_json(json_data)

        return (json_keys, json_values)
    
    def get_request_headers(self, request):

        return self.normalize_headers(request.headers.items())
    
    # Replace Django's multipart parser for this request only (same steps as
    # HttpRequest.parse_file_upload) to record the raw file names
    def set_multipart_parser(self, request):

        def parse_file_upload(META, post_data):
            request.upload_handlers = ImmutableList(
                request.upload_handlers,
                warning = 'You cannot alter upload handlers after the upload has been processed.'
            )
            parser = RawFileNamesParser(META, post_data, request.upload_handlers, request.encoding)
            parsed = parser.parse()
            setattr(request, self.RAW_FILE_NAMES_KEY, parser.raw_file_names)
            return parsed

        request.parse_file_upload = parse_file_upload

    # Get multipart upload files: [ [ filename, size ], ... ]
    def get_files(self, request):

        # Accessing FILES parses the body, which records the raw file names
        uploaded_files = [ uploaded_file for field_name, field_files in request.FILES.lists() for uploaded_file in field_files ]
        raw_file_names = getattr(request, self.RAW_FILE_NAMES_KEY, None)

        # Body parsed before PyRASP (by another middleware): sanitized names only
        if raw_file_names is None:
            files_list = [ [ uploaded_file.name, uploaded_file.size ] for uploaded_file in uploaded_files ]

        # Raw names matched to the uploaded files through their sanitized name,
        # dropped files ('..') have no size
        else:
            sizes = {}
            for uploaded_file in uploaded_files:
                sizes.setdefault(uploaded_file.name, []).append(uploaded_file.size)
            files_list = [ [ raw_name, sizes[sanitized_name].pop(0) if sizes.get(sanitized_name) else 0 ]
                           for raw_name, sanitized_name in raw_file_names ]

        return files_list

    ####################################################
    # JA4H FINGERPRINTING
    ####################################################

    def get_ja4h_params(self, request):

        method = request.method

        meta = request.META
        version = meta.get('SERVER_PROTOCOL', 'HTTP/1.1')
    
        request_headers = getattr(request, 'headers', None)

        headers = [ [ name.lower(), value.lower() ] for name, value in list(request_headers.items()) ]

        return (method, version, headers)
