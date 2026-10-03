import json
import time
from functools import wraps

from flask.wrappers import Response as FlaskResponseType

try:
    from .flaskrasp import FlaskRASP
    from .pyrasp import make_security_log, send_log
    from .pyrasp_data import ATTACKS_CHECKS
except ImportError:
    from pyrasp.flaskrasp import FlaskRASP
    from pyrasp.pyrasp import make_security_log, send_log
    from pyrasp.pyrasp_data import ATTACKS_CHECKS


class GcpRASP(FlaskRASP):

    def __init__(self, app = None, template = 'default', conf = None, params = {}, key = None, cloud_url = None):
        self.PLATFORM = 'Google Cloud Function'
        super(FlaskRASP, self).__init__(app, template, conf, params, key, cloud_url)

    ####################################################
    # CHECKS CONTROL
    ####################################################

    # GCP handler wrapper
    def register(self, f):
    
        @wraps(f)
        def decorator(request):

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
            response = None

            inbound_attack = self.check_inbound_attacks(host, request_method, request_path, source_ip, timestamp, request, ja4h_fingerprint)

            if inbound_attack:
                security_check = ATTACKS_CHECKS[inbound_attack['type']]

            if not inbound_attack or self.SECURITY_CHECKS.get(security_check) == 3:
                response = f(request)

            (response_content, status_code) = self.get_response_data(response, (host, request_path, source_ip, timestamp, ja4h_fingerprint))
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
    
    ####################################################
    # ROUTES
    ####################################################
            
    def get_app_routes(self, app):
        return {}
    
    ####################################################
    # RESPONSE PROCESSING
    # build_block_response() and build_redirect_response()
    # are inherited from FlaskRASP (identical implementation)
    ####################################################

    # Alter response
    def process_response(self, response, attack = None, log_only = True):

        status_code = self.get_response_status(response)

        if attack:
            if not log_only:
                response = self.make_attack_response(attack)
            self.REQUESTS['attacks'] += 1

        elif status_code == 200:
            self.REQUESTS['success'] += 1

        else:
            self.REQUESTS['errors'] += 1

        return response

    # Inspectable content (Flask streams are scanned chunk by chunk) and status code
    def get_response_data(self, response, context):

        body = response[0] if isinstance(response, tuple) else response

        if isinstance(body, FlaskResponseType):
            content = self.get_response_content(body, context)
        elif isinstance(body, (str, bytes, bytearray)):
            content = self.decode_response_body(body)
        elif isinstance(body, (dict, list)):
            content = self.decode_response_body(json.dumps(body))
        else:
            content = None

        return (content, self.get_response_status(response))

    # Status code of a view return value: Response, (body, status[, headers]) or body
    def get_response_status(self, response):

        status_code = 200

        if isinstance(response, FlaskResponseType):
            status_code = response.status_code
        elif isinstance(response, tuple) and len(response) >= 2 and isinstance(response[1], int):
            status_code = response[1]

        return status_code
    
    ####################################################
    # LOGGING
    ####################################################

    def log_security_event(self, event_type, source_ip, user = None, details = {}):

        log_data = make_security_log(self.APP_NAME, event_type, source_ip, self.LOG_FORMAT, user, details, False)

        try:
            send_log(log_data, self.LOG_SERVER, self.LOG_PORT, self.LOG_PROTOCOL, self.LOG_PATH)
        except Exception as e:
            self.print_screen(f'[PyRASP] Error sending logs : {str(e)}', level = 100)