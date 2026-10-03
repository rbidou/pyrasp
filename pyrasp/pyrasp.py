VERSION = '0.10.0'

import base64
import codecs
import hashlib
import json
import os
import re
import shutil
import socket
import sys
import time
import copy
from datetime import datetime
from pathlib import Path
from queue import Queue
from threading import Thread
from urllib.parse import parse_qsl, unquote, urlsplit

import cloudpickle
import importlib_resources
import jwt
import psutil
import requests
from loguru import logger

# DATA GLOBALS
try:
    from .pyrasp_data import (
        XSS_MODEL_VERSION, SQLI_MODEL_VERSION, PROMPT_MODEL_VERSION,
        CLOUD_FUNCTIONS,
        DEFAULT_CONFIG, DEFAULT_SECURITY_CHECKS, CONFIG_TEMPLATES,
        ATTACKS, ATTACKS_CHECKS, ATTACKS_CODES, BRUTE_FORCE_ATTACKS,
        SQL_INJECTIONS_VECTORS, XSS_VECTORS, COMMAND_INJECTIONS_VECTORS, PROMPT_INJECTIONS_VECTORS, CHARS_VECTORS,
        DLP_PATTERNS, PATTERN_CHECK_FUNCTIONS, B64_PATTERN, CHARS_PATTERNS,
        ATTACK_BLACKLIST, ATTACK_BOTS, ATTACK_BRUTE, ATTACK_CHARS, ATTACK_CMD, ATTACK_DECOY, ATTACK_DLP,
        ATTACK_FLOOD, ATTACK_HEADER, ATTACK_HPP, ATTACK_PROMPT, ATTACK_SPOOF, ATTACK_SQLI, ATTACK_UPLOAD,
        ATTACK_XSS, ATTACK_ZTAA,
        PROMPT_GPT_CONFIG,
        JA4H_EMPTY_HASH, JA4H_METHOD_CODES, JA4H_VERSION_CODES,
        ESCAPE_SIMPLE, ESCAPE_CODE,
        BOTS_JA4H_PATTERNS,
    )
except ImportError:
    from pyrasp.pyrasp_data import (
        XSS_MODEL_VERSION, SQLI_MODEL_VERSION, PROMPT_MODEL_VERSION,
        CLOUD_FUNCTIONS,
        DEFAULT_CONFIG, DEFAULT_SECURITY_CHECKS, CONFIG_TEMPLATES,
        ATTACKS, ATTACKS_CHECKS, ATTACKS_CODES, BRUTE_FORCE_ATTACKS,
        SQL_INJECTIONS_VECTORS, XSS_VECTORS, COMMAND_INJECTIONS_VECTORS, PROMPT_INJECTIONS_VECTORS, CHARS_VECTORS,
        DLP_PATTERNS, PATTERN_CHECK_FUNCTIONS, B64_PATTERN, CHARS_PATTERNS,
        ATTACK_BLACKLIST, ATTACK_BOTS, ATTACK_BRUTE, ATTACK_CHARS, ATTACK_CMD, ATTACK_DECOY, ATTACK_DLP,
        ATTACK_FLOOD, ATTACK_HEADER, ATTACK_HPP, ATTACK_PROMPT, ATTACK_SPOOF, ATTACK_SQLI, ATTACK_UPLOAD,
        ATTACK_XSS, ATTACK_ZTAA,
        PROMPT_GPT_CONFIG,
        JA4H_EMPTY_HASH, JA4H_METHOD_CODES, JA4H_VERSION_CODES,
        ESCAPE_SIMPLE, ESCAPE_CODE,
        BOTS_JA4H_PATTERNS,
    )

# IP
IP_COUNTRY = {}
STOP_LOG_THREAD = False
STOP_BEACON_THREAD = False
LOG_QUEUE = None

# CHARACTER ESCAPE
_ESCAPE_RE = re.compile(ESCAPE_CODE, re.DOTALL)

# Local Path
BASE_DIR = Path(__file__).resolve().parent

# LOG FUNCTIONS
def make_security_log(application, event_type, source_ip, log_format = 'syslog', user = None, event_details = {}, resolve_country = True):

    # Get source country
    if resolve_country:
        try:
            country = get_ip_country(source_ip)
        except:
            country = 'Private'
    else:
        country = ''

    if log_format.lower() == 'syslog':

        time = datetime.now().strftime(r'%Y/%m/%d %H:%M:%S')
        codes = ''
        if event_details.get('codes'):
            codes = ' - '.join(event_details['codes'])

        action = event_details.get('action') or 0

        data = f'[{time}] '
        data += ' - '.join([
            f'"{application}"',
            f'"{event_type}"',
            f'"{source_ip}"',
            f'"{country}"',
            f'"{codes}"',
            f'"{action}"'
        ])

        if event_details.get('location') and event_details.get('payload'):
            location = event_details['location']
            payload = event_details['payload']
            data += ' - '+f'"{location}:{payload}"'

    elif log_format.lower() == 'json':

        data = {
            'time': datetime.now().strftime(r'%Y/%m/%d %H:%M:%S'),
            'application': application,
            'log_data': [ event_type, source_ip, country, event_details ]
        }

    elif log_format.lower() == 'pcb':

        data = {
            'application': application,
            'log_type': 'security',
            'log_data': [ event_type, source_ip, country, user, event_details ]
        }

    return data

def get_ip_country(source_ip):

    global IP_COUNTRY

    if not source_ip in IP_COUNTRY:
        ip_request = requests.get('http://ip-api.com/json/'+source_ip)
        if ip_request.status_code == 200:
            ip_details = ip_request.json()
            country = ip_details.get('country') or 'Private'
            IP_COUNTRY[source_ip] = country
    else:
        country = IP_COUNTRY[source_ip]

    return country

def log_thread(rasp_instance, input, server, port, protocol = 'udp', path = '/logs', debug = False):

    transport = None
    sock = None
    protocol = protocol.lower()

    if protocol in [ 'http', 'https' ]:
        if not path.startswith('/'):
            path = '/'+path
        server_url = f'{protocol}://{server}:{port}{path}'
        transport = 'webhook'
    elif protocol == 'udp':
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        transport = 'udp'
    elif protocol == 'tcp':
        transport = 'tcp'       # connected lazily, kept open across logs
    elif protocol == 'file':
        transport = 'file'

    for log_data in iter(input.get, '--STOP--'):

        try:

            str_log_data = log_data if isinstance(log_data, str) else json.dumps(log_data)

            if transport == 'webhook':
                requests.post(server_url, json=log_data, timeout=1)

            elif transport == 'udp':
                # One datagram per log, no connection needed
                sock.sendto(str_log_data.encode('utf-8'), (server, port))

            elif transport == 'tcp':
                # Newline-delimited so the receiver can split the stream
                payload = (str_log_data + '\n').encode('utf-8')
                for attempt in (1, 2):
                    try:
                        if sock is None:
                            sock = socket.create_connection((server, port), timeout=1)
                        sock.sendall(payload)
                        break
                    except OSError:
                        # Peer closed or connection broken: drop it and retry once
                        if sock:
                            sock.close()
                        sock = None
                        if attempt == 2:
                            raise

            elif transport == 'file':
                logger.warning(str_log_data)

        except Exception as e:
            if debug:
                print(f'[PyRASP] Error sending logs : {str(e)}')

    if sock:
        sock.close()

    rasp_instance.print_screen('[+] Logging process stopped', init=True, new_line_up = False)

# SYNCHRONOUS LOGGING (serverless agents)
def send_log(log_data, server, port, protocol = 'udp', path = '/logs', timeout = 1):

    """
    Sends one security log synchronously.
    Transport is selected by LOG_PROTOCOL, as in log_thread():
        udp        : one datagram per log
        tcp        : one connection per log, newline-delimited
        http(s)    : POST with a JSON body to <protocol>://<server>:<port><path>
    Raises on failure: the caller decides how to handle the error.
    """

    protocol = (protocol or '').lower()
    str_log_data = log_data if isinstance(log_data, str) else json.dumps(log_data)

    if protocol in ('http', 'https'):
        if not path.startswith('/'):
            path = '/' + path
        requests.post(f'{protocol}://{server}:{port}{path}', json=log_data, timeout=timeout)

    elif protocol == 'udp':
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(str_log_data.encode('utf-8'), (server, port))

    elif protocol == 'tcp':
        # Timeout applies to connect() too: an unreachable server cannot stall the request
        with socket.create_connection((server, port), timeout=timeout) as sock:
            sock.sendall((str_log_data + '\n').encode('utf-8'))

# BEACON
def beacon_thread(rasp_instance):

    counter = 0

    while True :

        try:

            time.sleep(1)
            counter += 1

            if STOP_BEACON_THREAD:
                rasp_instance.print_screen('[+] Stopping beacon process', init=True, new_line_up = False)
                break

            if counter % rasp_instance.BEACON_DELAY == 0:
                counter = 0
                rasp_instance.send_beacon()

        except:
            pass
        
def handle_kb_interrupt(rasp_instance, sig, frame):
    rasp_instance.__del__()
    sys.exit()

# MULTIPART
# Content-Disposition parameters: each one starts at ';', so that 'name'
# never matches inside 'filename'
DISPOSITION_PARAM = re.compile(r';\s*([\w\-]+\*?)\s*=\s*("(?:[^"\\]|\\.)*"|[^;]*)')

def parse_content_disposition(disposition):

    """
    'Content-Disposition: form-data; name="file"; filename="a.jpg"' -> ('file', ['a.jpg'])
    Returns the field name and the declared file names (empty list for a text field).
    Every declared file name is returned (filename and filename*), so that a
    malicious name cannot hide behind a harmless one.
    """

    field_name = None
    filenames = []

    for match in DISPOSITION_PARAM.finditer(disposition):

        param = match.group(1).lower()
        value = match.group(2).strip()

        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = re.sub(r'\\(.)', r'\1', value[1:-1])

        if param == 'name':
            field_name = value

        elif param == 'filename':
            filenames.append(value)

        elif param == 'filename*':
            # RFC 5987: charset'language'percent-encoded value
            extended = re.match(r"([\w\-]+)'[^']*'(.*)", value)
            if extended:
                try:
                    value = unquote(extended.group(2), encoding=extended.group(1), errors='replace')
                except LookupError:
                    value = unquote(extended.group(2), errors='replace')
            filenames.append(value)

    # De-duplicate, preserve order
    seen = set()
    filenames = [ f for f in filenames if not (f in seen or seen.add(f)) ]

    return field_name, filenames

def recode_header_text(value):

    """
    Restore UTF-8 text from a header value decoded as Latin-1 by the server
    (PEP 3333 / Starlette): 'Ð°dmin' -> 'аdmin'.
    Returns the value unchanged when not Latin-1 encodable or not valid UTF-8.
    """

    try:
        recoded = value.encode('latin-1').decode('utf-8')
    except (UnicodeEncodeError, UnicodeDecodeError):
        recoded = value         # already text, or not valid UTF-8

    return recoded

class DlpStreamScanner():
    
    def __init__(self, rasp, context):

        self.rasp = rasp
        self.context = context      # (host, request_path, source_ip, timestamp, ja4h_fingerprint)
        self.decoder = codecs.getincrementaldecoder('utf-8')(errors = 'replace')
        self.tail = ''
        self.done = False

    # True when the chunk holds a leak and the stream must be cut before it
    def scan(self, chunk):

        cut = False

        if not self.done:

            text = chunk if isinstance(chunk, str) else self.decoder.decode(bytes(chunk))
            text = self.tail + text
            attack = self.rasp.check_dlp(text)
            self.tail = text[-self.rasp.DLP_STREAM_OVERLAP:]

            # Only the first leak is reported: scanning stops
            if attack:
                self.done = True
                cut = self.rasp.handle_stream_attack(attack, *self.context)

        return cut

class ScannedStream():

    def __init__(self, chunks, scanner):

        self.chunks = chunks
        self.iterator = iter(chunks)
        self.scanner = scanner
        self.cut = False

    def __iter__(self):
        return self

    def __next__(self):

        if self.cut:
            raise StopIteration

        chunk = next(self.iterator)

        if self.scanner.scan(chunk):
            self.cut = True
            raise StopIteration

        return chunk

    def close(self):

        close = getattr(self.chunks, 'close', None)
        if close is not None:
            close()

class PyRASP():

    ####################################################
    # GLOBAL VARIABLES
    ####################################################

    # Template & Configuration
    TEMPLATE = 'default'
    CONFIG = {}

    # ROUTES
    ROUTES = []

    # LOGGING
    LOG_QUEUE = None
    LOG_WORKER = None
    LOG_THREAD = None

    # BEACON
    BEACON_THREAD = None

    # KEY
    KEY = None
    
    # Attacks detection
    # Requests counters per IP, separated as each check has its own ratio and delay:
    # flood (requests to BRUTE_AND_FLOOD_PATHS) and error responses (brute force)
    FLOOD_IP_LIST = {}
    ERROR_IP_LIST = {}
    BLACKLIST = {}
    BLACKLIST_NEW = []

    # LOGS
    LOG_ENABLED = False

    # Misc
    INIT_VERBOSE = 0

    # PLATFORM
    PLATFORM = 'Unknown'

    # REQUESTS
    REQUESTS = {
        'success': 0,
        'errors': 0,
        'attacks': 0
    }

    # RESPONSE INSPECTION
    INSPECT_CONTENT_TYPES = [
        'text/', 'application/json', 'application/xml',
        'application/javascript', 'application/x-www-form-urlencoded'
    ]
    STREAMING_CONTENT_TYPES = ('text/event-stream', 'multipart/x-mixed-replace')
    MAX_BODY_INSPECT = 1 * 1024 * 1024
    DLP_STREAM_OVERLAP = 256            # longer than the longest DLP pattern match

    # API DATA
    API_CONFIG = {}
    API_BLACKLIST = []
    API_STATUS = {
        'version': '',
        'blacklist': 0,
        'xss_loaded': False,
        'sqli_loaded': False,
        'config': 'Default'
    }
    
    ####################################################
    # CONSTRUCTOR & DESTRUCTOR
    ####################################################

    def __init__(self, app = None, template = 'default', conf = None, params = {}, key = None, cloud_url = None):

        # Set init verbosity
        if 'VERBOSE' in params:
            self.INIT_VERBOSE = self.VERBOSE = params['VERBOSE']
        else:
            self.INIT_VERBOSE = self.VERBOSE = 10

        # Start display
        self.print_screen(f'### PyRASP v{VERSION} ##########', init=True, new_line_up=True)
        self.print_screen(f'[+] Starting PyRASP: {self.PLATFORM}', init=True, new_line_up=False)

        #
        # Get Routes
        #

        self.ROUTES = self.get_app_routes(app)

        #
        # Configuration
        #

        self.__set_config(template, conf, params, key, cloud_url)
        self.__apply_config()

        #
        # Security
        #

        # Register security checks
        if not app is None:
            self.register_security_checks(app)

        # Load ML models

        self.load_ml_models()

        # Agent status
        self.API_STATUS['version'] = VERSION
        self.API_STATUS['xss_loaded'] = self.XSS_MODEL_LOADED
        self.API_STATUS['sqli_loaded'] = self.SQLI_MODEL_LOADED
        self.API_STATUS['prompt_loaded'] = self.PROMPT_MODEL_LOADED

        #
        # Multithreading - Logs & Beacon (not for AWS, GCP & Azure)
        #

        if not self.PLATFORM in CLOUD_FUNCTIONS:

            # Start logging thread
            if self.LOG_ENABLED:
                self.start_logging()

            # Start beacon thread
            if getattr(self, 'BEACON', None):
                self.start_beacon()

        else:

            # Serverless: no background process, first beacon sent at startup,
            # then from the request handlers through beacon_if_due()
            self.LAST_BEACON = time.time()
            if getattr(self, 'BEACON', None):
                self.send_beacon()

        self.print_screen('[+] PyRASP succesfully started', init=True)
        self.print_screen('############################', init=True, new_line_down=True)

    def __del__(self):

        if not self.PLATFORM in CLOUD_FUNCTIONS:

            if getattr(self, 'BEACON', None):
                global STOP_BEACON_THREAD
                STOP_BEACON_THREAD = True

            if self.LOG_ENABLED and self.LOG_QUEUE is not None:
                self.LOG_QUEUE.put('--STOP--')

        return

    ####################################################
    # SECURITY SETUP
    ####################################################

    def load_ml_models(self):

        self.XSS_MODEL_LOADED = False
        self.SQLI_MODEL_LOADED = False
        self.PROMPT_MODEL_LOADED = False

        self.load_xss_model()
        self.load_sqli_model()
        self.load_prompt_model()        
        
    def load_xss_model(self):
 
        if self.SECURITY_CHECKS.get('xss'):
            # Load XSS ML model
            xss_model_file = 'xss_model-'+XSS_MODEL_VERSION

            ## From source
            try:
                self.xss_model = cloudpickle.load(open(BASE_DIR / 'data' / xss_model_file,'rb'))
            except Exception as e:
                pass
            else:
                self.XSS_MODEL_LOADED = True

            ## From package
            if not self.XSS_MODEL_LOADED:
                try:
                    xss_model_file = importlib_resources.files('pyrasp') / 'data' / xss_model_file
                    self.xss_model = cloudpickle.load(open(xss_model_file,'rb'))
                except:
                    pass
                else:
                    self.XSS_MODEL_LOADED = True

            if not self.XSS_MODEL_LOADED:
                self.print_screen('[!] XSS model not loaded', init=False, new_line_up = False)
            else:
                self.print_screen('[+] XSS model loaded', init=True, new_line_up = False)

    def load_sqli_model(self):

        if self.SECURITY_CHECKS.get('sqli'):
            # Load SQLI ML model
            sqli_model_file = 'sqli_model-'+SQLI_MODEL_VERSION
            
            ## From source
            try:
                self.sqli_model = cloudpickle.load(open(BASE_DIR / 'data' / sqli_model_file,'rb'))
            except:
                pass
            else:
                self.SQLI_MODEL_LOADED = True

            ## From package
            if not self.SQLI_MODEL_LOADED:
                try:
                    sqli_model_file = importlib_resources.files('pyrasp') / 'data' / sqli_model_file
                    self.sqli_model = cloudpickle.load(open(sqli_model_file,'rb'))
                except Exception as e:
                    pass
                else:
                    self.SQLI_MODEL_LOADED = True

            if not self.SQLI_MODEL_LOADED:
                self.print_screen('[!] SQLI model not loaded', init=False, new_line_up = False)
            else:
                self.print_screen('[+] SQLI model loaded', init=True, new_line_up = False)

    def load_prompt_model(self):

        ## Prompt Injection model loaded only if enabled in configuration
        if self.SECURITY_CHECKS.get('prompt'):

            # Heavy dependencies (torch, tiktoken) are only imported when prompt injection detection is enabled
            import torch
            import tiktoken
            try:
                from .pyrasp_gpt import GPTModel
            except ImportError:
                from pyrasp.pyrasp_gpt import GPTModel

            # Init model
            self.prompt_model = GPTModel(PROMPT_GPT_CONFIG)

            prompt_model_file = 'prompt_model-'+PROMPT_MODEL_VERSION

            prompt_model_filenames = [
                'data/' + prompt_model_file,
                importlib_resources.files('pyrasp') / 'data' / prompt_model_file
            ]

            for prompt_model_filename in prompt_model_filenames:
                try:
                    self.prompt_model.load_state_dict(torch.load(prompt_model_filename, map_location=torch.device('cpu'), weights_only=True))
                except Exception as e:
                    pass
                else:
                    self.PROMPT_MODEL_LOADED = True
                    break

            if self.PROMPT_MODEL_LOADED:

                # Set model in eval mode
                self.prompt_model.eval()

                # Setup Tokenizer
                self.gpt2_tokenizer = tiktoken.get_encoding('gpt2')


            if not self.PROMPT_MODEL_LOADED:
                self.print_screen('[!] Prompt Injection model not loaded', init=False, new_line_up = False)
            else:
                self.print_screen('[+] Prompt Injection model loaded', init=True, new_line_up = False)

    def register_security_checks(self, app):
        pass

    ####################################################
    # BEACON & UPDATES
    ####################################################

    def start_beacon(self):

        self.print_screen('[+] Starting beacon process', init=True, new_line_up = False)
        self.BEACON_THREAD = Thread(target=beacon_thread, args=(self, ), daemon=True)
        self.BEACON_THREAD.start()
        
    def send_beacon(self):

        #
        # BEACON
        #

        beacon_url = self.BEACON_URL
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent

        data = { 
            'key': self.KEY, 
            'version': VERSION,
        }

        # Telemetry
        if self.TELEMETRY_DATA:
            telemetry = {
                'cpu': cpu,
                'memory': mem,
                'requests': self.REQUESTS
            }

            data['telemetry'] = telemetry
            
        # Blacklist exchange
        if self.BLACKLIST_SHARE:
            data['blacklist'] = self.BLACKLIST_NEW
        
        error = False

        # Send requets to server
        try:
            r = requests.post(beacon_url, json=data, timeout=5)
        except Exception as e:
            self.print_screen('[PyRASP] Error connecting to cloud server')
            error = True

        # Check response status
        if not error:
            if r.status_code == 403:
                self.print_screen('[!] Invalid or missing agent key', init = True)
                error = True
            elif r.status_code == 404:
                self.print_screen('[!] Security profile not found', init = True)
                error = True
            elif r.status_code == 500:
                self.print_screen('[PyRASP] Server error')
                error = True

        # Get beacon response JSON
        if not error:
            try:
                server_response = r.json()
                server_message = server_response['message']
                server_result = server_response['status']
                server_data = server_response['data']
            except:
                self.print_screen('[!] Corrupted server response')
                error = True

        # Check response status
        if not error:
            if not server_result:
                self.print_screen(f'[!] Error: {server_message}')
                error = True
    
        #
        # RESPONSE HANDLING
        #

        # Reset requests count and blacklist
        if not error:
            self.REQUESTS = {
                'success': 0,
                'errors': 0,
                'attacks': 0
            }
            self.BLACKLIST_NEW = []

        # Update blasklist
        if not error:

            blacklist_update = server_data.get('blacklist')

            if blacklist_update:

                # Add new blacklist entries
                new_blacklist_entries = blacklist_update.get('new') or []
                time_now = int(time.time())
                for new_entry in new_blacklist_entries:
                    if not new_entry in self.BLACKLIST:
                        self.BLACKLIST[new_entry] = time_now
            
                # Force remove blacklist entries
                remove_blacklist_entries = blacklist_update.get('remove') or []
                for remove_entry in remove_blacklist_entries:
                    if remove_entry in self.BLACKLIST:
                        del self.BLACKLIST[remove_entry]           

        # Set configuration
        if not error and server_data.get('config'):

            self.print_screen('[PyRASP] Loading new configuration')

            log_keys = [ 'LOG_ENABLED', 'LOG_FORMAT', 'LOG_PROTOCOL', 'LOG_SERVER', 'LOG_PORT', 'LOG_PATH', 'LOG_FILE_SIZE' ]
            beacon_keys = [ 'BEACON', 'BEACON_DELAY', 'BEACON_URL' ]
            previous = { k: self.CONFIG.get(k) for k in log_keys + beacon_keys }

            self.__update_config(server_data.get('template'), server_data['config'])
            self.__apply_config()

            config_changes = {
                'logs': any(self.CONFIG.get(k) != previous[k] for k in log_keys),
                'beacon': any(self.CONFIG.get(k) != previous[k] for k in beacon_keys)
            }

            # Restart services
            if not self.PLATFORM in CLOUD_FUNCTIONS and config_changes['logs']:
                if self.LOG_ENABLED:
                    self.start_logging(restart = self.LOG_THREAD is not None and self.LOG_THREAD.is_alive())
                elif self.LOG_THREAD is not None and self.LOG_THREAD.is_alive():
                    self.LOG_QUEUE.put('--STOP--')

    def beacon_if_due(self):

        """
        Serverless agents: sends a beacon when BEACON_DELAY seconds
        have elapsed since the last one. Called at each request.
        """

        if not getattr(self, 'BEACON', None):
            return

        time_now = time.time()

        if time_now > getattr(self, 'LAST_BEACON', 0) + self.BEACON_DELAY:
            # Set before sending: an unreachable server is retried after BEACON_DELAY,
            # not at every request
            self.LAST_BEACON = time_now
            self.send_beacon()

    ####################################################
    # LOGGING
    ####################################################

    def start_logging(self, restart = False):

        if self.LOG_PROTOCOL.lower() == 'file':
            logger.remove()
            logger.add(self.LOG_PATH, level='INFO', rotation=f'{self.LOG_FILE_SIZE}MB', format='{message}')
            
        if restart:
            self.LOG_QUEUE.put('--STOP--')
            while self.LOG_THREAD.is_alive():
                time.sleep(1)

        self.print_screen('[+] Starting logging process', init=True, new_line_up = False)
        self.LOG_QUEUE = Queue()
        self.LOG_THREAD = Thread(target=log_thread, args=(self, self.LOG_QUEUE, self.LOG_SERVER, self.LOG_PORT, self.LOG_PROTOCOL, self.LOG_PATH ), daemon=True)
        self.LOG_THREAD.start()
        
    def log_security_event(self, event_type, source_ip, user = None, details = {}):

        if self.LOG_QUEUE is not None:

            try:
                security_log = make_security_log(self.APP_NAME, event_type, source_ip, self.LOG_FORMAT, user, details, self.RESOLVE_COUNTRY)
            except:
                pass
            else:
                self.LOG_QUEUE.put(security_log)

    ####################################################
    # ROUTES
    ####################################################
            
    def get_app_routes(self, app):
        return {}

    ####################################################
    # CONFIGURATION
    ####################################################

    def __set_config(self, template, conf, params, key, cloud_url):

        """
        Loads each configuration source and keeps it separately:
            FILE_CONFIG   : local configuration file
            REMOTE_CONFIG : configuration provided by the cloud server
            PARAMS_CONFIG : constructor params, then set_config() changes
        The running configuration is built by __build_config()
        """

        # Local configuration file (wrapped { "config": {...} } or flat format)
        file_config = self.__get_file_config(conf if isinstance(conf, (str, os.PathLike)) else None)
        if isinstance(file_config.get('config'), dict):
            file_config = file_config['config']
        self.FILE_CONFIG = copy.deepcopy(file_config)

        # Cloud server
        remote_init = self.__get_cloud_config(cloud_url, key)
        remote_config = remote_init.get('config')
        self.REMOTE_CONFIG = copy.deepcopy(remote_config) if isinstance(remote_config, dict) else {}

        # Constructor parameters
        self.PARAMS_CONFIG = copy.deepcopy(params) if isinstance(params, dict) else {}

        # Template: cloud server > constructor argument > default
        template = remote_init.get('template') or template
        if not template in CONFIG_TEMPLATES:
            if template is not None:
                self.print_screen(f'[!] Unknown template "{template}", using "default"', init=True, new_line_up = False)
            template = 'default'
        self.TEMPLATE = template

        self.print_screen(f'[+] Loading template configuration: {self.TEMPLATE}', init=True, new_line_up = False)

        # Build config
        self.CONFIG = self.__build_config()

        # Set Blacklist
        remote_blacklist = remote_init.get('blacklist')
        self.BLACKLIST = dict(remote_blacklist) if isinstance(remote_blacklist, dict) else {}

        # Configuration type for get_status()
        if remote_init:
            self.API_STATUS['config'] = 'Cloud'
        elif self.FILE_CONFIG:
            self.API_STATUS['config'] = 'Local'
        else:
            self.API_STATUS['config'] = 'Default'

    def __build_config(self):

        """
        Builds the running configuration, in the same order as at startup:
            DEFAULT_CONFIG < template < FILE_CONFIG < REMOTE_CONFIG < PARAMS_CONFIG
        Parameters are replaced as a whole, except 'SECURITY_CHECKS.<check>' keys
        (written by set_config()) which change a single security check.
        """

        config = copy.deepcopy(DEFAULT_CONFIG)

        layers = [
            CONFIG_TEMPLATES[self.TEMPLATE],
            self.FILE_CONFIG,
            self.REMOTE_CONFIG,
            self.PARAMS_CONFIG
        ]

        for layer in layers:
            for config_key, config_value in layer.items():
                if config_key.startswith('SECURITY_CHECKS.'):
                    security_check = config_key.split('.', 1)[1]
                    config['SECURITY_CHECKS'][security_check] = config_value
                else:
                    config[config_key] = copy.deepcopy(config_value)

        return config
    
    def __apply_config(self):

        # Set config
        try:
            for config_key, config_value in self.CONFIG.items():
                setattr(self, config_key, config_value)
        except:
            pass
        else:
            self.API_CONFIG = self.CONFIG

    def __update_config(self, template, new_config):

        """
        Applies a configuration update received from the cloud server
            template = None or running template => new_config merged into REMOTE_CONFIG
            template = other known template     => template changed, REMOTE_CONFIG replaced by new_config
            template = unknown                  => warning, handled as None
        The running configuration is then rebuilt from all sources.
        """

        new_config = new_config if isinstance(new_config, dict) else {}

        if template is not None and not template in CONFIG_TEMPLATES:
            self.print_screen(f'[!] Unknown template "{template}", keeping "{self.TEMPLATE}"')
            template = None

        if template is None or template == self.TEMPLATE:
            self.REMOTE_CONFIG.update(copy.deepcopy(new_config))
        else:
            self.TEMPLATE = template
            self.REMOTE_CONFIG = copy.deepcopy(new_config)
            self.print_screen(f'[+] Loading template configuration: {template}', init=True, new_line_up = False)

        self.CONFIG = self.__build_config()
    
    def __get_cloud_config(self, cloud_url, key):

        cloud_config = True
        config =  {}

        # Check cloud configuration
        self.CLOUD_URL = cloud_url or os.environ.get('PYRASP_CLOUD_URL')

        if self.CLOUD_URL is None:
            cloud_config = False

        # Check key
        if cloud_config:
            
            self.KEY = key or os.environ.get('PYRASP_KEY')

            if self.KEY is None:
                self.print_screen('[!] Agent key could not be found.', init=True, new_line_up = True)
                cloud_config = False

        # Get configuration
        if cloud_config:

            data = { 'key': self.KEY, 'version': VERSION, 'platform': self.PLATFORM, 'routes': self.ROUTES }
            error = False

            # Send requets to server
            try:
                r = requests.post(self.CLOUD_URL, json=data, timeout=5)
            except Exception as e:
                self.print_screen('[PyRASP] Error connecting to cloud server')
                error = True

            # Check response status
            if not error:
                if r.status_code == 403:
                    self.print_screen('[!] Invalid or missing agent key', init = True)
                    error = True
                elif r.status_code == 404:
                    self.print_screen('[!] Security profile not found', init = True)
                    error = True
                elif r.status_code == 500:
                    self.print_screen('[PyRASP] Server error')
                    error = True

            # Check response format
            if not error:
                try:
                    server_response = r.json()
                except:
                    self.print_screen('[!] Corrupted server response')
                    error = True

            # Get response data
            if not error:
                try:
                    server_message = server_response['message']
                    server_result = server_response['status']
                except:
                    self.print_screen('[!] Corrupted server response')
                    error = True

            # Check response status
            if not error:
                if not server_result:
                    self.print_screen(f'[!] Error: {server_message}')
                    error = True
                else:
                    config = server_response['data']

        return config

    def __get_file_config(self, conf_file):

        config = {}

        # Argument first, then environment variable
        self.CONF_FILE = conf_file or os.environ.get('PYRASP_CONF') or os.environ.get('CONF_FILE')

        if not self.CONF_FILE:
            return config

        self.print_screen(f'[+] Loading configuration from {self.CONF_FILE}', init = True, new_line_up = False)

        try:
            with open(self.CONF_FILE) as f:
                config = json.load(f)
        except Exception as e:
            self.print_screen(f'[!] Error reading {self.CONF_FILE}: {str(e)}', init = True, new_line_up = False)
            config = {}

        if not isinstance(config, dict):
            self.print_screen(f'[!] Invalid configuration in {self.CONF_FILE}: JSON object expected', init = True, new_line_up = False)
            config = {}

        return config

    ####################################################
    # ATTACK HANDLING
    ####################################################

    def handle_attack(self, attack, host, request_path, source_ip, timestamp, ja4h_fingerprint = None):

        attack_id = attack['type']
        attack_check = ATTACKS_CHECKS[attack_id]
        attack_details = attack.get('details') or {}
        attack_payload = None
        if attack_details and attack_details.get('payload'):
            attack_payload = attack_details['payload']
            try:
                attack_payload_b64 = base64.b64encode(attack_details['payload'].encode()).decode()
                attack_details['payload'] = attack_payload_b64
            except:
                pass

        action = None

        # Action
        ## Generic case
        if not attack_id == 0:
            action = self.SECURITY_CHECKS[attack_check] 
        ## Blacklist
        else:
            action = 2

        attack_details['action'] = action

        # Attack type
        if ATTACKS_CODES.get(attack_id):
            attack_details['codes'] = ATTACKS_CODES[attack_id]

        if not self.BLACKLIST_OVERRIDE and action == 2:
            self.blacklist_ip(source_ip, timestamp, attack_check)

        # Path
        attack_details['path'] = request_path

        # Ja4h fingerprint
        if self.LOG_JA4H_FINGERPRINT and not ja4h_fingerprint is None:
            attack_details['ja4h_fingerprint'] = ja4h_fingerprint


        # Print screen
        try:
            self.print_screen(f'[!] {ATTACKS[attack_id]}: {attack["details"]["location"]} -> {attack_payload}')
            self.print_screen(f'[!] {attack}', level = 100)
        except:
            self.print_screen(f'[!] {ATTACKS[attack_id]}: No details')
    
        # Log
        if self.LOG_ENABLED:
            self.log_security_event(attack_check, source_ip, None, attack_details)

    ####################################################
    # CHECKS CONTROL
    ####################################################

    # Inbound attacks
    def check_inbound_attacks(self, host, request_method, request_path, source_ip, timestamp, request, ja4h_fingerprint, inject_vectors = None):

        (attack_location, attack_payload) = (None, None)

        ignore = False
        attack_id = None
        attack = None

        # Check if source is whitelisted
        whitelist = False

        for whitelist_source in self.WHITELIST:
            if source_ip.startswith(whitelist_source):
                whitelist = True

        # Not whitelisted, going through security tests
        if not whitelist:

            ### Rules to be applied to all requests

            # Check if source IP is already blacklisted
            if not self.BLACKLIST_OVERRIDE:
                attack = self.check_blacklist(source_ip, timestamp)
            
            # Check if client is a bot
            if attack == None:
                if self.SECURITY_CHECKS.get('bots'):
                    attack = self.check_bots(ja4h_fingerprint)

            # Check Zero-Trust
            if attack == None:
                if self.SECURITY_CHECKS.get('ztaa'):
                    attack = self.check_ztaa(request)

            # Check host
            if attack == None:
                if self.SECURITY_CHECKS.get('spoofing') and len(self.HOSTS) > 0:
                    attack = self.check_host(host)

            # Decoy
            if attack == None:
                if self.SECURITY_CHECKS.get('decoy'):
                    attack = self.check_decoy(request_path)
                
            # Check if routing rule exists
            if attack == None:
                if self.SECURITY_CHECKS.get('path'):
                    attack = self.check_route(request, request_method, request_path)

            # Check if path is to be ignored
            if attack == None:
                if self.check_ignore_path(request_path):
                    ignore = True
            else:
                ignore = True

            ### Rules to be applied to NOT ignored path
            if not ignore:

                # Check brute force and flood on vulnerable paths
                if attack == None:
                    if self.SECURITY_CHECKS.get('flood'):
                        attack = self.flood_and_brute_check(request_path, source_ip, timestamp)
                            
                # Check HTTP Parameter Pollution
                if attack == None:
                    if self.SECURITY_CHECKS.get('hpp'):
                        attack = self.check_hpp(request)

                # Get injectable params
                if attack == None and inject_vectors == None:
                    inject_vectors = self.get_vectors(request)
                    inject_vectors = self.remove_exceptions(inject_vectors)
                    
                # Check headers
                if attack == None:
                    if self.SECURITY_CHECKS.get('headers'):
                        attack = self.check_headers(inject_vectors)

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

                # Files upload
                if attack == None:
                    if self.SECURITY_CHECKS.get('upload'):
                        files = self.get_files(request)
                        attack = self.check_multipart_files(files)

        return attack

    # Outbound attacks
    def check_outbound_attacks(self, response_content, request_path, source_ip, timestamp, status_code, attack_type):

        attack = None
        error = False
        check_brute = False
        check_dlp = False

        if status_code >= 400:
            error = True

        # Check errors floods and brute force
        if error:
            check_brute = True
        elif attack_type in BRUTE_FORCE_ATTACKS:
            check_brute = True


        if check_brute:

            if self.SECURITY_CHECKS.get('brute'):
                attack = self.flood_and_brute_check(request_path, source_ip, timestamp, error=True)

        # Check DLP
        if not error and attack is None:
            check_dlp = True

        if check_dlp:

            if self.SECURITY_CHECKS.get('dlp') and not response_content == None:
                attack = self.check_dlp(response_content)

        return attack
    
    # Alter response
    def process_response(self, response, attack = None, log_only = True):

        if attack:
            if not log_only:
                response = self.make_attack_response(attack)
            self.REQUESTS['attacks'] += 1

        elif response.status_code == 200:
            self.REQUESTS['success'] += 1

        else:
            self.REQUESTS['errors'] += 1

        if self.CHANGE_SERVER:
            response = self.change_server(response)

        return response

    ####################################################
    # RESPONSE BODY INSPECTION
    ####################################################

    # Buffered response: inspectable text, identity encoding, known and limited size
    def should_inspect_response(self, content_type, content_length, content_encoding = None):

        content_type = (content_type or '').lower()

        try:
            length = int(content_length)
        except (TypeError, ValueError):
            length = None

        return all([
            not content_type.startswith(self.STREAMING_CONTENT_TYPES),
            any(content_type.startswith(t) for t in self.INSPECT_CONTENT_TYPES),
            (content_encoding or 'identity').lower() == 'identity',
            length is not None and length <= self.MAX_BODY_INSPECT
        ])

    # Streamed response: text (SSE included), identity encoding, DLP enabled
    def should_scan_stream(self, content_type, content_encoding = None):

        content_type = (content_type or '').lower()

        return all([
            bool(self.SECURITY_CHECKS.get('dlp')),
            any(content_type.startswith(t) for t in self.INSPECT_CONTENT_TYPES),
            (content_encoding or 'identity').lower() == 'identity'
        ])

    # Body as text, None when too large: never raises
    def decode_response_body(self, body, charset = 'utf-8'):

        content = None

        if isinstance(body, str):
            content = body if len(body) <= self.MAX_BODY_INSPECT else None

        elif body is not None and len(body) <= self.MAX_BODY_INSPECT:
            try:
                content = bytes(body).decode(charset or 'utf-8')
            except (LookupError, UnicodeDecodeError):
                content = bytes(body).decode('latin-1', errors = 'replace')

        return content

    # Leak found in a stream: headers are gone, log it and tell if the stream must be cut
    def handle_stream_attack(self, attack, host, request_path, source_ip, timestamp, ja4h_fingerprint = None):

        self.handle_attack(attack, host, request_path, source_ip, timestamp, ja4h_fingerprint = ja4h_fingerprint)
        self.REQUESTS['attacks'] += 1

        return self.SECURITY_CHECKS.get(ATTACKS_CHECKS[attack['type']]) != 3

    # Asynchronous body iterator scanned chunk by chunk, ending before a blocked leak
    async def scan_async_stream(self, chunks, scanner):

        try:
            async for chunk in chunks:
                if scanner.scan(chunk):
                    break
                yield chunk
        finally:
            aclose = getattr(chunks, 'aclose', None)
            if aclose is not None:
                await aclose()

    ####################################################
    # SECURITY FUNCTIONS
    ####################################################

    # Check Bots
    def check_bots(self, ja4h_fingerprint = None):

        attack = None

        if ja4h_fingerprint is not None and any([ re.match(regexp, ja4h_fingerprint, re.IGNORECASE) for regexp in BOTS_JA4H_PATTERNS]):
            attack = {
                'type': ATTACK_BOTS,
                'details': {
                    'location': 'ja4h_fingerprint',
                    'payload': ja4h_fingerprint
                }
            } 

        return attack

    # Check Zero-Trust
    def check_ztaa(self, request):

        attack = None
        attack_location = None
        attack_payload = None
        ztaa_jwt = None

        headers = self.get_request_headers(request)

        # Check ZTAA JWT

        ztaa_key_header_name = self.ZTAA_HEADER
        ztaa_valid = True

        for request_header in headers:
            if request_header.lower() == ztaa_key_header_name.lower():
                ztaa_jwt = headers[request_header]
                break

        if ztaa_jwt is None:
            ztaa_valid = False

        if ztaa_valid:

            ztaa_valid = False

            if not self.ZTAA_KEYS is None:

                if not isinstance(self.ZTAA_KEYS, list):
                    ztaa_keys = [ self.ZTAA_KEYS ]
                else:
                    ztaa_keys = self.ZTAA_KEYS

                for ztaa_key in ztaa_keys:

                    try:
                        ztaa_assertion = jwt.decode(ztaa_jwt, ztaa_key, algorithms=['HS512'])
                    except Exception as e:
                        pass
                    else:
                        ztaa_valid = True
                        break

        if not ztaa_valid:
            attack_location = 'ztaa_jwt'
            attack_payload = 'Invalid Assertion'

        if not ztaa_valid:
            attack = {
                'type': ATTACK_ZTAA,
                'details': {
                    'location': attack_location,
                    'payload': attack_payload
                }
            }

        # Check browser version
        if attack is None and self.ZTAA_BROWSER_VERSION:
            if not ztaa_assertion.get('latest'):
                attack = {
                'type': ATTACK_ZTAA,
                'details': {
                    'location': 'browser_version',
                    'payload': ztaa_assertion.get('browser') or 'Invalid browser'
                }
            }


        return attack

    # Check if a rule matches the request
    def check_route(self, request, request_method, request_path):

        attack = None

        return attack
    
    # Check floods and brute force attempts
    def flood_and_brute_check(self, request_path, source_ip, timestamp, error = False):

        result = False
        attack = None
        attack_type = ATTACK_FLOOD

        ignore = True
        ratio = self.FLOOD_RATIO
        delay = self.FLOOD_DELAY
        ip_list = self.FLOOD_IP_LIST

        if error:
            ratio = self.ERROR_FLOOD_RATIO
            delay = self.ERROR_FLOOD_DELAY
            ip_list = self.ERROR_IP_LIST

        ## All requests: check if path is in Brute & Flood vulnerable paths
        for bf_pattern in self.BRUTE_AND_FLOOD_PATHS:
            if re.search(bf_pattern, request_path):
                ignore = False
                break

        ## Error response: all requests to be processed
        if error:
            ignore = False
            attack_type = ATTACK_BRUTE

        ## Request to be processed
        if not ignore:
            # Check if source IP already identified or out of restricted delay
            # If not create / reinitialize structure
            if not source_ip in ip_list or timestamp > ip_list[source_ip]['timestamp'] + delay:
                ip_list[source_ip] = {
                    'timestamp': timestamp,
                    'count': 0
                }

            # Increase counters
            ip_list[source_ip]['count'] += 1

            # Set result if requests count is greater than the ratio
            if ip_list[source_ip]['count'] > ratio:
                result = True

        if result:
            attack = {
                'type': attack_type,
                'details': { 
                    'location': 'path',
                    'payload': request_path
                }
            }

        return attack 

    # Check Host header
    def check_host(self, full_host):

        attack = None

        host = full_host.split(':')[0]

        if not any([
            host in self.HOSTS,
            full_host in self.HOSTS]):
            attack = {
                'type': ATTACK_SPOOF,
                'details': {
                    'location': 'host',
                    'payload': host
                }
            }

        return attack

    # Check Decoy
    def check_decoy(self, request_path):

        attack = None

        for decoy_route in self.DECOY_ROUTES:

            # Get decoy route configuration 
            if type(decoy_route) == list:
                pattern = decoy_route[0]
                match_type = decoy_route[1]
                if not match_type in PATTERN_CHECK_FUNCTIONS:
                    match_type = 'starts'
            else:
                pattern = decoy_route
                match_type = 'starts'

            if self.check_pattern(request_path, pattern, match_type):

                attack = {
                    'type': ATTACK_DECOY,
                    'details': {
                        'location': 'path',
                        'payload': request_path
                    }
                }

                break

        return attack

    # Check sql injection
    def check_sqli(self, vectors):

        sql_injection = False
        attack = None
        sqli_probability = None

        # Get relevant vectors
        for vector_type in SQL_INJECTIONS_VECTORS:

            if not vector_type in vectors:
                continue

            # Get collected values
            for injection in vectors[vector_type]:

                str_injection = str(injection)

                # Machine Learning check
                sqli_probability = self.sqli_model.predict_proba([str_injection.lower()])[0]
                if sqli_probability[1] > self.SQLI_PROBA:
                    sql_injection = True
                    attack = {
                        'type': ATTACK_SQLI,
                        'details': {
                            'location': vector_type,
                            'payload': injection,
                            'engine': 'machine learning',
                            'score': sqli_probability[1]
                        }
                    }
                    break

                if sql_injection:
                    break

            if sql_injection:
                break

        return attack

    # Check XSS
    def check_xss(self, vectors):

        xss = False
        attack = None
        xss_probability = None
        injection = None

        # Get relevant vectors
        for vector_type in XSS_VECTORS:

            if not vector_type in vectors:
                continue

            # Get request values
            for injection in vectors[vector_type]:

                str_injection = str(injection)

                xss_probability = self.xss_model.predict_proba([str_injection.lower()])[0]
                if xss_probability[1] > self.XSS_PROBA:
                    xss = True
                    attack = {
                        'type': ATTACK_XSS,
                        'details': {
                            'location': vector_type,
                            'payload': injection,
                            'engine': 'machine learning',
                            'score': xss_probability[1]
                        }
                    }
                    break

            if xss:
                break

        return attack

    # Check HPP
    def check_hpp(self, request):

        hpp = False
        hpp_param = None
        attack = None

        query_string = self.get_query_string(request)
        posted_data = self.get_posted_data(request)

        variables = {}

        for qs_variable in query_string:

            if not qs_variable in variables:
                variables[qs_variable] = []

            variables[qs_variable].extend(query_string[qs_variable])

        for post_variable in posted_data:

            if not post_variable in variables:
                variables[post_variable] = []

            variables[post_variable].extend(posted_data[post_variable])

        for variable in variables:
            if len(variables[variable]) > 1:
                hpp = True
                hpp_param = variable
                break

        if hpp:
            attack = {
                'type': ATTACK_HPP,
                'details': {
                    'location': 'param',
                    'payload': hpp_param
                }
            }

        return attack

    # Check command injection
    def check_cmdi(self, vectors):

        command_injection = False
        attack = None

        # Get relevant vectors
        for vector_type in COMMAND_INJECTIONS_VECTORS:

            if not vector_type in vectors:
                continue

            # Get request values
            for injection in vectors[vector_type]:

                command_pattern = r'(?:[&;|]|\$IFS)+\s*(\w+)'
                commands = re.findall(command_pattern, str(injection)) or []

                for command in commands:
                    if shutil.which(command):
                        command_injection = True
                        break
                
                if command_injection == True:
                    break

            if command_injection == True:
                break

        if command_injection:
            attack = {
                'type': ATTACK_CMD,
                'details': {
                    'location': vector_type,
                    'payload': injection
                }
            }

        return attack

    # Check headers
    def check_headers(self, vectors):

        wrong_header = False
        header_name = None
        attack = None

        for header in vectors['headers_names']:
            if header.lower() in self.FORBIDDEN_HEADERS:
                wrong_header = True
                header_name = header
                break

        if wrong_header:
            attack = {
                'type': ATTACK_HEADER,
                'details': {
                    'location': 'header',
                    'payload': header_name
                }
            }


        return attack

    # Check response content for DLP
    def check_dlp(self, content):

        attack = None
        payload = None
        payload_type = None

        if payload == None and self.DLP_PHONE_NUMBERS:
            payload = self.check_dlp_patterns('phone', content)
            payload_type = 'Phone Number'

        if payload == None and self.DLP_CC_NUMBERS:
            payload = self.check_dlp_patterns('cc', content)
            payload_type = 'Credit Card'

        if payload == None and self.DLP_PRIVATE_KEYS:
            payload = self.check_dlp_patterns('key', content)
            payload_type = 'Private Key'

        if payload == None and self.DLP_HASHES:
            payload = self.check_dlp_patterns('hash', content)
            payload_type = 'Password Hash'

        if payload == None and self.DLP_WINDOWS_CREDS:
            payload = self.check_dlp_patterns('windows', content)
            payload_type = 'Windows Credentials'

        if payload == None and self.DLP_LINUX_CREDS:
            payload = self.check_dlp_patterns('linux', content)
            payload_type = 'Linux Credentials'

        if payload == None and self.DLP_API:
            payload = self.check_dlp_patterns('api', content)
            payload_type = 'API Key'

        if payload:
            if not self.DLP_LOG_LEAKED_DATA:
                payload = payload_type
            attack = {
                'type': ATTACK_DLP,
                'details': {
                    'location': 'content',
                    'payload': payload
                }
            }

        return attack
    
    def check_dlp_patterns(self, patterns, content):

        leaked = None

        for pattern in DLP_PATTERNS[patterns]:
            match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
            if not match is None:
                leaked = match.group()
                break

        return leaked

    # Check Prompt Injection
    def check_prompt_injection(self, vectors):

        # Already loaded by load_prompt_model(): this is a sys.modules lookup
        import torch

        prompt_injection = False
        attack = None
        injection_probability = None
        injection = None

        # Get relevant vectors
        for vector_type in PROMPT_INJECTIONS_VECTORS:

            if not vector_type in vectors:
                continue

            # Get request values
            for injection in vectors[vector_type]:

                injection_ids = self.gpt2_tokenizer.encode(str(injection))
                max_length = self.prompt_model.pos_emb.weight.shape[0]
        
                injection_ids = injection_ids[:max_length]

                pad_token_id = PROMPT_GPT_CONFIG['pad_id']
                injection_ids += [pad_token_id] * (max_length - len(injection_ids))
                injection_tensor = torch.tensor(injection_ids).unsqueeze(0)
                
                with torch.no_grad():
                    logits = self.prompt_model(injection_tensor)[:, -1, :]
                probas = torch.softmax(logits, dim = -1)

                injection_probability = probas.tolist()[0]

                if injection_probability[1] > 0.5:
                        prompt_injection = True
                        attack = {
                            'type': ATTACK_PROMPT,
                            'details': {
                                'location': vector_type,
                                'payload': injection,
                                'engine': 'large language model',
                                'score': injection_probability[1]
                            }
                        }
                        break

                if prompt_injection:
                    break

        return attack

    # Check Multipart File Upload
    def check_multipart_files(self, files):
        
        attack = None

        if files is None:
            return attack

        if len(files) > 0 and self.UPLOAD_FILES == False:

            attack = {
                'type': ATTACK_UPLOAD,
                'details': {
                    'location': 'multipart',
                    'payload': 'file upload attempts'
                }
            }

        else:

            for filename, file_size in files:


                # Check filename
                if any([
                    '..' in filename,
                    '/' in filename,
                    '\\' in filename
                ]):
                    attack = {
                        'type': ATTACK_UPLOAD,
                        'details': {
                            'location': 'filename',
                            'payload': filename
                        }
                    }

                    break

                # Check length

                if file_size > self.UPLOAD_MAX_SIZE * 1000000:
                    attack = {
                        'type': ATTACK_UPLOAD,
                        'details': {
                            'location': 'size',
                            'payload': file_size
                        }
                    }

                    break

                # Check extension
                extension = os.path.splitext(filename)[1]
                extension = extension[1:]

                if not extension.lower() in self.UPLOAD_EXTENSIONS:
                    attack = {
                        'type': ATTACK_UPLOAD,
                        'details': {
                            'location': 'extension',
                            'payload': extension
                        }
                    }

                    break

        return attack

    # Check Characters
    def check_characters(self, vectors):

        attack = None
        suspicious_characters = False

        for vector_type in CHARS_VECTORS:

            if not vector_type in vectors:
                continue

            for injection in vectors[vector_type]:

                if self.CHARS_CYRILLIC:
                    match = re.search(CHARS_PATTERNS['cyrillic'], injection)
                    if not match is None:
                        suspicious_characters = True
                        break

                if self.CHARS_NONPRINTABLE:
                    match = re.search(CHARS_PATTERNS['non_printable'], injection)
                    if not match is None:
                        suspicious_characters = True
                        break

                if self.CHARS_INVISIBLE:
                    match = re.search(CHARS_PATTERNS['invisible'], injection)
                    if not match is None:
                        suspicious_characters = True
                        break

            if suspicious_characters: 
                break

        if suspicious_characters:

            attack = {
                'type': ATTACK_CHARS,
                'details': {
                    'location': vector_type
                }
            }

        return attack

    ####################################################
    # RESPONSE PROCESSING
    ####################################################

    def change_server(self, response):

        response.headers['Server'] = self.SERVER_HEADER

        return response
    
    def make_attack_response(self, attack = None):

        attack_type = attack['type']
        attack_code = ATTACKS_CHECKS[attack_type]
        attack_action = 2 if attack_code == 'blacklist' else self.SECURITY_CHECKS[attack_code]

        if attack_action == 2 and not self.BLACKLIST_OVERRIDE:
            action = self.BLACKLIST_ACTION
            status_code = self.BLACKLIST_STATUS_CODE
            content = self.BLACKLIST_ACTION_CONTENT

        else:
            action = self.BLOCK_ACTION
            status_code = self.BLOCK_STATUS_CODE
            content = self.BLOCK_ACTION_CONTENT

        if action == 'block':
            response = self.build_block_response(status_code, content)
        elif action == 'redirect':
            response = self.build_redirect_response(status_code, content)
        else:
            response = self.build_block_response(status_code, content)

        return response
    
    def build_block_response(self, status_code, content):
        return None
    
    def build_redirect_response(self, status_code, content):
        return None

    ####################################################
    # BLACKLIST
    ####################################################
    
    # Check if source IP is in blacklist
    def check_blacklist(self, source_ip, timestamp):

        result = True
        attack = None

        # Source IP is in the blacklist
        if source_ip in self.BLACKLIST:
            # Blacklist delay expired: removing source from blacklist
            if timestamp > self.BLACKLIST[source_ip] + self.BLACKLIST_DELAY:
                del self.BLACKLIST[source_ip]
                result = False
        
        # Source not in the blacklist
        else:
            result = False

        if result:
            attack = {
                'type': ATTACK_BLACKLIST,
                'details': {
                    'location': 'source_ip',
                    'payload': source_ip
                }
            }
        
        return attack
    
    # Blacklist source IP
    def blacklist_ip(self, source_ip, timestamp, attack_type = None):

        result = True

        if not source_ip in self.BLACKLIST:
            self.BLACKLIST[source_ip] = timestamp
            self.BLACKLIST_NEW.append([source_ip, int(timestamp)])

        return result
    
    ####################################################
    # DECOY
    ####################################################

    # Unused for now
    def decoy(self, request):

        return self.GTFO_MSG, 4

    ####################################################
    # PARAMS & VECTORS
    ####################################################
    
    # Get request params
    def get_params(self, request):
        pass
    
    # Get request injection vectors
    def get_vectors(self, request):

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
            'json_values': []
        }

        # Request path
        request_path_elements = self.get_request_path(request)
        for path_element in request_path_elements:
            if len(path_element):
                vectors['path'].extend(self.decode_value(path_element))

        # Query strings
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
        (json_keys, json_values) = self.get_json_data(request)
        
        vectors['json_keys'] = json_keys

        for json_value in json_values:
            vectors['json_values'].extend(self.decode_value(json_value, decode=True, b64=False))    

        # Headers
        vectors.update(self.get_headers_vectors(self.get_request_headers(request)))

        # JSON in vectors
        (extracted_keys, extracted_values) = self.extract_json_vectors(vectors)

        vectors['json_keys'].extend(extracted_keys)
        vectors['json_values'].extend(extracted_values)

        return vectors

    # Split request headers into cookies, user agent, referer and other headers vectors
    def get_headers_vectors(self, headers):

        vectors = { 'headers_names': [], 'headers_values': [], 'cookies': [], 'user_agent': [], 'referer': [] }

        for header in headers:

            header_name = header.lower()

            # Check if header not in whitelist
            if not any([ self.check_pattern(header_name, i[0].lower(), i[1]) for i in self.WHITELIST_HEADERS ]):

                # Cookies
                if header_name == 'cookie':
                    for cookie_value in self.get_cookie_values(headers[header]):
                        vectors['cookies'].extend(self.decode_value(cookie_value))

                # User Agent
                elif header_name == 'user-agent':
                    vectors['user_agent'] = self.decode_value(headers[header], decode=True, b64=False)

                # Referer
                elif header_name == 'referer':
                    vectors['referer'] = self.get_referer_vectors(headers[header])

                # Other headers
                else:
                    vectors['headers_names'].append(header)
                    vectors['headers_values'].append(headers[header])

        return vectors

    # Move JSON structures found in any vector to JSON vectors
    def extract_json_vectors(self, vectors):

        extracted_keys = []
        extracted_values = []

        for vector_type in vectors:
            (plain_payloads, new_keys, new_values) = self.split_json_payloads(vectors[vector_type])
            vectors[vector_type] = plain_payloads
            extracted_keys.extend(new_keys)
            extracted_values.extend(new_values)

        return (extracted_keys, extracted_values)

    # Split payloads into plain payloads and keys / values of JSON structures (nested JSON strings included)
    def split_json_payloads(self, payloads):

        plain_payloads = []
        json_keys = []
        json_values = []

        for payload in payloads:

            structure = self.load_json_structure(payload)

            if structure is None:
                plain_payloads.append(payload)

            else:
                (new_keys, new_values) = self.analyze_json(structure)
                (nested_plain, nested_keys, nested_values) = self.split_json_payloads(new_values)
                json_keys.extend(new_keys + nested_keys)
                json_values.extend(nested_plain + nested_values)

        return (plain_payloads, json_keys, json_values)

    # Load a payload as a JSON structure (dict or list), None otherwise
    def load_json_structure(self, payload):

        structure = None

        try:
            loaded = json.loads(payload)
        except (ValueError, TypeError):
            pass
        else:
            if type(loaded) in (dict, list):
                structure = loaded

        return structure

    # Remove exceptions from vectors
    def remove_exceptions(self, inject_vectors):

        for vector in inject_vectors:
            inject_vectors[vector] = [ payload for payload in inject_vectors[vector] if not self.is_exception(payload) ]

        return inject_vectors

    # Check if a payload matches one of the configured exceptions
    def is_exception(self, payload):

        result = False

        for exception in self.EXCEPTIONS:

            if type(exception) == list:
                pattern = exception[0]
                match_type = exception[1] if exception[1] in PATTERN_CHECK_FUNCTIONS else 'match'
            else:
                pattern = exception
                match_type = 'match'

            if self.check_pattern(payload, pattern, match_type):
                result = True
                break

        return result


    def get_request_path(self, request):

        return []
    
    def get_query_string(self, request):

        return {}
    
    def get_posted_data(self, request):

        return {}

    def get_json_data(self, request):

        return ([],[])
    
    def get_request_headers(self, request):

        return {}

    # Build a headers dict of UTF-8 text from (name, value) pairs, merging repeated headers
    def normalize_headers(self, header_items):

        headers = {}

        for (name, value) in header_items:
            text = recode_header_text(value)
            separator = '; ' if name.lower() == 'cookie' else ', '
            headers[name] = f'{headers[name]}{separator}{text}' if name in headers else text

        return headers

    # Extract cookie values from a Cookie header
    def get_cookie_values(self, cookie_header):

        cookie_values = []
        rebuilt_values = []

        for cookie in cookie_header.split(';'):

            if not cookie.strip():
                continue

            # Split on the first '=' only: the value may contain '='
            cookie_parts = cookie.split('=', 1)
            cookie_value = cookie_parts[-1].strip()
            cookie_values.append(cookie_value)

            # Nameless fragment: the rest of the previous value, cut on a ';'
            if len(cookie_parts) == 1 and rebuilt_values:
                rebuilt_values[-1] = f'{rebuilt_values[-1]};{cookie}'
            elif len(cookie_parts) == 2:
                rebuilt_values.append(cookie_value)

        # Rebuilt values are only new when fragments were appended
        cookie_values.extend(value for value in rebuilt_values if value not in cookie_values)

        # Percent-encoded values (RFC 6265 clients): also inspect the decoded form
        decoded_values = [ unquote(value) for value in cookie_values ]
        cookie_values.extend(value for value in decoded_values if value not in cookie_values)

        return cookie_values

    # Get Referer injection vectors: decoded path elements, query variables and values
    def get_referer_vectors(self, referer):

        try:
            url = urlsplit(referer)
        except ValueError:
            elements = [ referer ]
        else:
            path = unquote(url.path)
            path_elements = [ element for element in path.split('/') if len(element) ]
            query_elements = [ element for pair in parse_qsl(url.query, keep_blank_values=True) for element in pair if len(element) ]
            elements = list(dict.fromkeys([ element for element in [ path ] + path_elements + query_elements if len(element) ]))

        vectors = []
        for element in elements:
            vectors.extend(self.decode_value(element, decode=True, b64=False))

        return vectors

    # Get multipart upload files
    def get_files(self, request):
        pass

    ####################################################
    # JA4H FINGERPRINTING
    ####################################################

    def calculate_ja4h_fingerprint(self, request):

        (http_method, http_version, headers) = self.get_ja4h_params(request)

        method_code = self._ja4h_method_code(http_method)
        version_code = self._ja4h_version_code(http_version)

        headers_names = []
        cookies = []
        has_cookie = False
        has_referer = False
        language = None

        for name, value in headers:
            name = name.lower()
            if name == 'cookie':
                has_cookie = True
                cookies.extend(self._ja4h_parse_cookie_header(value))
                continue
            if name == 'referer':
                has_referer = True
                continue
            if name == 'accept-language' and language is None:
                language = self._ja4h_language_code(value)

            headers_names.append(name)

        cookies.sort(key=lambda pair: (pair[0], pair[1] is not None, pair[1] or ''))

        headers_count = min(len(headers_names), 99)

        ja4h_parts = []

        ja4h_a = ''.join(
            (
                method_code,
                version_code,
                'c' if has_cookie else 'n',
                'r' if has_referer else 'n',
                f'{headers_count:02d}',
                language or '0000',
            )
        )
        ja4h_parts.append(ja4h_a)

        ja4h_b = self._ja4h_hash12(','.join(headers_names))
        ja4h_parts.append(ja4h_b)

        ja4h_c = self._ja4h_hash12(','.join(name for name, _ in cookies))
        ja4h_parts.append(ja4h_c)

        ja4h_d = self._ja4h_hash12(','.join( name if value is None else f'{name}={value}' for name, value in cookies ))
        ja4h_parts.append(ja4h_d)

        ja4h_fingerprint = '_'.join(ja4h_parts)

        return ja4h_fingerprint

    def get_ja4h_params(self, request):

        method = JA4H_METHOD_CODES['GET']
        version = JA4H_VERSION_CODES['HTTP/1.1']
        headers = []

        return (method, version, headers)

    def _ja4h_parse_cookie_header(self, value):

        pairs = []

        for crumb in (value or '').split(';'):
            crumb = crumb.strip()
            if not crumb:
                continue
            name, sep, val = crumb.partition('=')
            pairs.append((name.strip(), val if sep else None))

        return pairs

    def _ja4h_language_code(self, value = None):

        if value is None:
            return '0000'
        
        primary = value.split(',')[0].split(';')[0].strip()
        letters = ''.join(c for c in primary if c.isalpha())[:4].lower()

        return letters.ljust(4, '0')

    def _ja4h_hash12(self, joined):
    
        if not joined:
            return JA4H_EMPTY_HASH

        return hashlib.sha256(joined.encode('utf-8')).hexdigest()[:12]
 
    def _ja4h_method_code(self, method):
        
        method = (method or '').upper()

        method_code = JA4H_METHOD_CODES.get(method) or (method.lower() + '00')[:2]

        return method_code
 
    def _ja4h_version_code(self, version):

        if isinstance(version, (int, float)):
            version = str(version)

        key = (version or '').strip().upper()
        if key in JA4H_VERSION_CODES:
            return JA4H_VERSION_CODES[key]
        # Fall back to major/minor parsing, e.g. 'HTTP/1.2' -> '12'.
        digits = key.split('/')[-1]
        parts = digits.split('.')
        try:
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
        except (ValueError, IndexError):
            return '00'
        return f'{major % 10}{minor % 10}'

    ####################################################
    # UTILS
    ####################################################

    # Check if path is to be ignored
    def check_ignore_path(self, request_path):

        result = False

        # Check if path is to be ignored
        for ignore_pattern in self.IGNORE_PATHS:
            if re.search(ignore_pattern, request_path):
                result = True
                break

        return result

    # Get structure keys and variables
    def analyze_json(self, structure):

        keys = []
        values = []

        # List
        if type(structure) is list:
            for el in structure:

                # Element is a structure
                if any( [ type(el) is list, type(el) is dict ]):
                    (new_keys, new_values) = self.analyze_json(el)
                    keys.extend(new_keys)
                    values.extend(new_values)

                # Element is a value
                else:

                    is_b64 = False

                    # B64 Decoding
                    if self.DECODE_B64 and re.search('^'+B64_PATTERN+'$', str(el)):
                
                        # B64 value double-check
                        try:
                            b64_value_bytes = base64.b64decode(str(el))
                            b64_value = b64_value_bytes.decode()

                        ## Not B64
                        except:
                            pass

                        ## B64
                        else:

                            is_b64 = True

                            ## Check if JSON
                            try:
                                json_value = json.loads(b64_value)
                            ### Not JSON
                            except:
                                values.append(b64_value)
                            ### JSON
                            else:
                                (b64_keys, b64_values) = self.analyze_json(json_value)
                                keys.extend(b64_keys)
                                values.extend(b64_values)

                    if not is_b64:

                        values.append(str(el))


            return(keys, values)
        

        # Dictionary
        elif type(structure) is dict:

            for new_key in structure:
                keys.append(new_key)
                el = structure[new_key]

                # Element is a structure
                if any( [ type(el) is list, type(el) is dict ]):
                    (new_keys, new_values) = self.analyze_json(el)
                    keys.extend(new_keys)
                    values.extend(new_values)

                # Element is a value
                else:

                    is_b64 = False

                    # B64 Decoding
                    if self.DECODE_B64 and re.search('^'+B64_PATTERN+'$', str(el)):
                
                        # B64 value double-check
                        try:
                            b64_value_bytes = base64.b64decode(str(el))
                            b64_value = b64_value_bytes.decode()

                        ## Not B64
                        except:
                            pass

                        ## B64
                        else:

                            is_b64 = True

                            ## Check if JSON
                            try:
                                json_value = json.loads(b64_value)
                            ### Not JSON
                            except:
                                values.append(b64_value)
                            ### JSON
                            else:
                                (b64_keys, b64_values) = self.analyze_json(json_value)
                                keys.extend(b64_keys)
                                values.extend(b64_values)

                    if not is_b64:

                        values.append(str(el))
  
            return(keys, values)
        
        return (keys, values)

    # Identifies and decode b64 values 
    def get_b64_values(self, param_value):

        b64_values = []

        values = re.findall(B64_PATTERN, param_value)

        for value in values:
            try:
                b64_value_bytes = base64.b64decode(value)
                b64_value = b64_value_bytes.decode()
            except:
                pass
            else:
                b64_values.append(b64_value)

        return b64_values
            
    # Display info
    def print_screen(self, text, level = 10, init = False, new_line_up = False, new_line_down = False):

        display = any([
            init and self.INIT_VERBOSE >= level,
            not init and self.VERBOSE >= level
        ])
            
        if display:
            if new_line_up:
                print()
            print(text)
            if new_line_down:
                print()

    # Decode
    def decode_value(self, value, decode = True, b64 = True):

        decoded_variables = [ value ]

        if decode:
            try:
                #decoded = value.encode().decode('unicode_escape')
                decoded = self._unescape(value)
            except:
                pass
            else:
                if not decoded == value:
                    decoded_variables.append(decoded)

        if b64:

            if self.DECODE_B64:
                decoded_values = self.get_b64_values(value)
                if len(decoded_values):
                    decoded_variables.extend(decoded_values)
        
        return decoded_variables

    def _unescape(self, value):

        if not isinstance(value, str) or '\\' not in value:
            return value

        def repl(m):
            seq = m.group(1)
            if len(seq) > 1:                      # \uXXXX or \xXX
                return chr(int(seq[1:], 16))
            return ESCAPE_SIMPLE.get(seq, '\\' + seq)

        return _ESCAPE_RE.sub(repl, value)

    # Pattern checking
    def check_pattern(self, text, pattern, match_type):

        match = False

        try:

            # Regular expression
            if match_type == 'regex':
                match = re.search(pattern, text)
            # Starts
            elif match_type == 'starts':
                match = text.startswith(pattern)
            # Ends
            elif match_type == 'ends':
                match = text.endswith(pattern)
            # Contains
            elif match_type == 'contains':
                match = pattern in text
            # Matches
            elif match_type == 'match':
                match = text == pattern
                
        except Exception as e:
            pass

        return match

    # Extact data
    def extract_data(self, data):

        input_vectors = []


        if isinstance(data, list):
            for data_item in data:
                input_vectors.extend(self.extract_data(data_item))
                

        elif isinstance(data, dict):
            for data_key, data_item in data.items():
                input_vectors.append(data_key)
                input_vectors.extend(self.extract_data(data_item))
                

        else:
            input_vectors.append(data)

        return input_vectors

    ####################################################
    # API
    ####################################################

    def get_config(self):

        return self.API_CONFIG

    def set_config(self, config_params):

        """
        Changes are stored in PARAMS_CONFIG, the highest priority source:
        they are kept when the configuration is rebuilt by a cloud update.
        """

        results = { 'success' : [], 'fail': [] }

        for key, value in config_params.items():

            # Single security check
            if key.startswith('SECURITY_CHECKS.'):
                security_check = key.split('.', 1)[1]
                if not security_check in DEFAULT_SECURITY_CHECKS:
                    results['fail'].append(key)
                    continue

            # Parameter
            elif not key in self.CONFIG:
                results['fail'].append(key)
                continue

            # Whole SECURITY_CHECKS dictionary: previous single check changes are dropped
            if key == 'SECURITY_CHECKS':
                for params_key in [ k for k in self.PARAMS_CONFIG if k.startswith('SECURITY_CHECKS.') ]:
                    del self.PARAMS_CONFIG[params_key]

            # Latest change applied last
            self.PARAMS_CONFIG.pop(key, None)
            self.PARAMS_CONFIG[key] = copy.deepcopy(value)
            results['success'].append(key)

        if results['success']:
            self.CONFIG = self.__build_config()
            self.__apply_config()

        return results
                   
    def get_blacklist(self):

        self.API_BLACKLIST = [ i for i in self.BLACKLIST ]

        return self.API_BLACKLIST
    
    def get_status(self):

        self.API_STATUS['blacklist'] = len(self.BLACKLIST)

        return self.API_STATUS

    def get_routes(self):

        return self.ROUTES


####################################################
# BACKWARD COMPATIBILITY
# `from pyrasp.pyrasp import FlaskRASP` keeps working:
# agents are imported lazily (PEP 562), so only the
# framework actually used is ever imported.
####################################################

_AGENTS = {
    'FlaskRASP': 'flaskrasp',
    'FastApiRASP': 'fastapirasp',
    'DjangoRASP': 'djangorasp',
    'LambdaRASP': 'lambdarasp',
    'GcpRASP': 'gcprasp',
    'AzureRASP': 'azurerasp',
    'McpHostRASP': 'mcphostrasp',
    'McpToolRASP': 'mcptoolrasp',
    'AsgiRASP': 'asgirasp',
    'WsgiRASP': 'wsgirasp',
    'AiohttpRASP': 'aiohttprasp'
}

def __getattr__(name):

    module_name = _AGENTS.get(name)

    if module_name is None:
        raise AttributeError(f'module {__name__!r} has no attribute {name!r}')

    import importlib

    try:
        module = importlib.import_module(f'.{module_name}', __package__)
    except (ImportError, TypeError):
        module = importlib.import_module(f'pyrasp.{module_name}')

    return getattr(module, name)
