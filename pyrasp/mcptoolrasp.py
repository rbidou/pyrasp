import inspect
import json
import time
from functools import wraps

import fastmcp
from fastmcp.server.dependencies import get_http_request

try:
    from .pyrasp import PyRASP
    from .pyrasp_data import ATTACKS_CHECKS
except ImportError:
    from pyrasp.pyrasp import PyRASP
    from pyrasp.pyrasp_data import ATTACKS_CHECKS


class McpToolRASP(PyRASP):

    def __init__(self, app = None, template = 'default', conf = None, params = {}, key = None, cloud_url = None):
        self.PLATFORM = 'MCP Tool'
        super().__init__(app, template, conf, params, key, cloud_url)
        if not self.APP_NAME:
            self.APP_NAME = app.name
        self.MCP_SERVER = app
        self.MCP_SERVER_SETTINGS = fastmcp.settings

    ####################################################
    # SECURITY CHECKS
    ####################################################

    # Register
    def register(self, f):

        # Asynchronous tool: the wrapper must be a coroutine function too,
        # so that FastMCP awaits it and the checks run on the actual result
        if inspect.iscoroutinefunction(f):

            @wraps(f)
            async def async_decorator(**kwargs):

                context = self.before_tool_call(kwargs)
                if context['blocked']:
                    return self.process_response()

                response = await f(**kwargs)

                return self.after_tool_call(context, response)

            return async_decorator

        # Synchronous tool
        @wraps(f)
        def decorator(**kwargs):

            context = self.before_tool_call(kwargs)
            if context['blocked']:
                return self.process_response()

            response = f(**kwargs)

            return self.after_tool_call(context, response)

        return decorator

    def before_tool_call(self, kwargs):

        """
        Inbound checks on tool arguments.
        Returns a context dictionary; context['blocked'] is True when the tool must not run.
        """

        (host, request_method, request_path, source_ip, timestamp) = self.get_params()

        context = {
            'host': host,
            'request_path': request_path,
            'source_ip': source_ip,
            'timestamp': timestamp,
            'ja4h_fingerprint': None,
            'inbound_attack': None,
            'blocked': False
        }

        # JA4H fingerprint: only available when the call comes through an HTTP transport
        if self.LOG_JA4H_FINGERPRINT or self.SECURITY_CHECKS.get('bots'):
            try:
                context['ja4h_fingerprint'] = self.calculate_ja4h_fingerprint(get_http_request())
            except Exception:
                pass

        # Inbound checks
        inbound_vectors = self.remove_exceptions(self.get_vectors(**kwargs))
        inbound_attack = self.check_inbound_attacks(inbound_vectors)

        if inbound_attack:
            context['inbound_attack'] = inbound_attack
            self.handle_attack(inbound_attack, host, request_path, source_ip, timestamp, ja4h_fingerprint = context['ja4h_fingerprint'])
            security_check = ATTACKS_CHECKS[inbound_attack['type']]
            context['blocked'] = self.SECURITY_CHECKS.get(security_check) != 3

        return context

    def after_tool_call(self, context, response):

        """
        Outbound checks on the tool result.
        Returns the result, or the block response.
        """

        # Inbound detection in log only mode: result returned unchanged
        if context['inbound_attack']:
            return response

        outbound_attack = self.check_outbound_attacks(response)

        if outbound_attack:
            self.handle_attack(outbound_attack, context['host'], context['request_path'], context['source_ip'], context['timestamp'], ja4h_fingerprint = context['ja4h_fingerprint'])
            security_check = ATTACKS_CHECKS[outbound_attack['type']]
            if self.SECURITY_CHECKS.get(security_check) != 3:
                return self.process_response()

        return response
    
    ####################################################
    # CHECKS CONTROL
    ####################################################

    def check_inbound_attacks(self, inject_vectors):

        attack = None

        # Check suspicious characters
        if attack == None:
            if self.SECURITY_CHECKS.get('chars'):
                attack = self.check_characters(inject_vectors)

        # Check command injection
        if attack == None:
            if self.SECURITY_CHECKS.get('command'):
                attack = self.check_cmdi(inject_vectors)

        # Check XSS
        if attack == None:
            if self.SECURITY_CHECKS.get('xss') and self.XSS_MODEL_LOADED:
                attack = self.check_xss(inject_vectors)

        # Check SQL injections
        if attack == None:
            if self.SECURITY_CHECKS.get('sqli') and self.SQLI_MODEL_LOADED:
                attack = self.check_sqli(inject_vectors)

        # Check Prompt injection
        if attack == None:
            if self.SECURITY_CHECKS.get('prompt') and self.PROMPT_MODEL_LOADED:
                attack = self.check_prompt_injection(inject_vectors)

        return attack
    
    def check_outbound_attacks(self, response_data):

        attack = None

        # Check DLP
        if self.SECURITY_CHECKS.get('dlp'):

            # Results that are not JSON-serializable (Pydantic models, dataclasses...)
            # are converted to text instead of skipping the check
            try:
                out_data = response_data if isinstance(response_data, str) else json.dumps(response_data, default=str)
            except Exception:
                out_data = str(response_data)

            attack = self.check_dlp(out_data)

        return attack
    
    def process_response(self):

        response = self.BLOCK_ACTION_CONTENT

        return response

    ####################################################
    # PARAMS & VECTORS
    ####################################################

    # Get request params
    def get_params(self):
        request_path = self.MCP_SERVER_SETTINGS.streamable_http_path
        request_method = 'POST'
        source_ip_list = '127.0.0.1'
        source_ip = source_ip_list.split(',')[0].strip()
        timestamp = time.time()
        host = self.APP_NAME
        return (host, request_method, request_path, source_ip, timestamp)

    def get_vectors(self, **kwargs):

        input_vectors = {
            'mcp_values': self.extract_data(kwargs)
        }
                
        return input_vectors

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
