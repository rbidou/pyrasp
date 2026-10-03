import base64
import json
import time
from functools import wraps
from urllib.parse import parse_qs

try:
    from .pyrasp import PyRASP, make_security_log, send_log
    from .pyrasp_data import ATTACKS_CHECKS
except ImportError:
    from pyrasp.pyrasp import PyRASP, make_security_log, send_log
    from pyrasp.pyrasp_data import ATTACKS_CHECKS


class LambdaRASP(PyRASP):

    def __init__(self, app = None, template = 'default', conf = None, params = {}, key = None, cloud_url = None):
        self.PLATFORM = 'AWS Lambda'
        super().__init__(app, template, conf, params, key, cloud_url)
       
    ####################################################
    # LOGGING
    ####################################################

    def start_logging(self, restart = False):
        pass
        
    ####################################################
    # CHECKS CONTROL
    ####################################################

    # AWS handler wrapper
    def register(self, f):
    
        @wraps(f)
        def decorator(request, context):

            # Sending beacons to get configuration and blacklist updates
            self.beacon_if_due()

            (host, request_method, request_path, source_ip, timestamp) = self.get_params(request)

            # Analyze request
            inbound_attack = None
            outbound_attack = None
            status_code = 200
            log_only = False
            security_check = None
            response = {}

            inbound_attack = self.check_inbound_attacks(host, request_method, request_path, source_ip, timestamp, request)

            if inbound_attack:
                security_check = ATTACKS_CHECKS[inbound_attack['type']]

            if not inbound_attack or self.SECURITY_CHECKS.get(security_check) == 3:
                response = f(request, context)

            # Set response params
            response_content_structure = response.get('body') or {}
            response_content = json.dumps(response_content_structure)

            status_code = response.get('statusCode') or self.DENY_STATUS_CODE
            inbound_attack_type = inbound_attack['type'] if inbound_attack else None

            # Analyze response
            outbound_attack = self.check_outbound_attacks(response_content, request_path, source_ip, timestamp, status_code, inbound_attack_type)

            if outbound_attack:
                security_check = ATTACKS_CHECKS[outbound_attack['type']]

            if outbound_attack:
                self.handle_attack(outbound_attack, host, request_path, source_ip, timestamp)
            elif inbound_attack:
                self.handle_attack(inbound_attack, host, request_path, source_ip, timestamp)

            # Check log only
            if security_check and self.SECURITY_CHECKS.get(security_check) == 3:
                log_only = True

            response = self.process_response(response, inbound_attack or outbound_attack, log_only = log_only)
                
            return response
            
        return decorator
    
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
    # RESPONSE PROCESSING
    ####################################################

    # Alter response
    def process_response(self, response, attack = None, log_only = True):

        if attack:
            if not log_only:
                response = self.make_attack_response()
            self.REQUESTS['attacks'] += 1

        elif response['statusCode'] == 200:
            self.REQUESTS['success'] += 1

        else:
            self.REQUESTS['errors'] += 1

        return response

    def make_attack_response(self):

        response = {
            'statusCode': self.DENY_STATUS_CODE,
            'body': json.dumps(self.BLOCK_ACTION_CONTENT)
        }

        return response

    ####################################################
    # PARAMS & VECTORS
    ####################################################

    def get_params(self, request):

        (host, request_method, request_path, source_ip, timestamp) = ('', '', '', '', time.time())


        context = request.get('requestContext')

        if context:

            host = context.get('domainName')

            if context.get('http'):
                http = context['http']
                request_path = http.get('path')
                request_method = http.get('method')
                source_ip = http.get('sourceIp')

            else:
                request_path = request.get('path')
                request_method = request.get('httpMethod')
                if context and context.get('identity'):
                    source_ip = context['identity'].get('sourceIp')

        return (host, request_method, request_path, source_ip, timestamp)
    
    def get_query_string(self, request):

        query_string = request.get('multiValueQueryStringParameters')

        if query_string is None:

            query_string = {}

            qs_data = request.get('queryStringParameters')  or {}
            
            for qs_variable in qs_data:
                query_string[qs_variable] = [ qs_data[qs_variable] ]

        return query_string
    
    def get_posted_data(self, request):

        posted_data = {}

        headers = { name.lower(): value for (name, value) in (request.get('headers') or {}).items() }
        content_type = (headers.get('content-type') or '').split(';')[0].strip().lower()

        # Multipart and JSON bodies are not form data
        if content_type != 'multipart/form-data' and 'json' not in content_type:
            posted_data = parse_qs(self.get_body(request), keep_blank_values=True)

        return posted_data

    # Request body as text, base64-decoded when API Gateway encoded it
    def get_body(self, request):

        body = request.get('body') or ''

        if request.get('isBase64Encoded'):
            try:
                body = base64.b64decode(body).decode('utf-8', errors='replace')
            except ValueError:
                pass

        return body
    
    def get_request_path(self, request):
        
        request_path = ''

        context = request.get('requestContext')

        if context:

            if context.get('http'):
                http = context['http']
                request_path = http.get('path')

            else:
                request_path = request.get('path')

        return request_path
    
    def get_json_data(self, request):

        json_keys = []
        json_values = []

        try:
            json_data = json.loads(self.get_body(request))
            (json_keys, json_values) = self.analyze_json(json_data)
        except:
            pass

        return (json_keys, json_values)
    
    def get_request_headers(self, request):

        #headers = request.get('headers') or {}
        headers = {}

        return headers
