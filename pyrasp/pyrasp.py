VERSION = '0.1.2'

from pprint import pprint
from flask import request
import time
import re
import sqlparse
import sqlite3
import pickle
import base64
import shutil
import json
import requests
import socket
from datetime import datetime
from threading import Thread
import signal
import pkg_resources


# MULTIPROCESSING
from multiprocessing import Process, Queue

# DATA GLOBALS
try:
    from pyrasp.pyrasp_data import DATA_VERSION, XSS_MODEL_VERSION
    from pyrasp.pyrasp_data import PCB_SERVER, PCB_PROTOCOL
    from pyrasp.pyrasp_data import DEFAULT_CONFIG
    from pyrasp.pyrasp_data import ATTACKS, ATTACKS_CHECKS
    from pyrasp.pyrasp_data import SQL_INJECTIONS_POINTS, SQL_INJECTIONS_SIGNATURES, SQL_INJECTIONS_VECTORS
    from pyrasp.pyrasp_data import XSS_VECTORS
    from pyrasp.pyrasp_data import COMMAND_INJECTIONS_VECTORS
    from pyrasp.pyrasp_data import ATTACK_BLACKLIST, ATTACK_CMD, ATTACK_DECOY, ATTACK_FLOOD, ATTACK_FORMAT, ATTACK_HEADER, ATTACK_HPP, ATTACK_PATH, ATTACK_SPOOF, ATTACK_SQLI, ATTACK_XSS
except:
    from pyrasp_data import DATA_VERSION, XSS_MODEL_VERSION
    from pyrasp_data import PCB_SERVER, PCB_PROTOCOL
    from pyrasp_data import DEFAULT_CONFIG
    from pyrasp_data import ATTACKS, ATTACKS_CHECKS
    from pyrasp_data import SQL_INJECTIONS_POINTS, SQL_INJECTIONS_SIGNATURES, SQL_INJECTIONS_VECTORS
    from pyrasp_data import XSS_VECTORS
    from pyrasp_data import COMMAND_INJECTIONS_VECTORS
    from pyrasp_data import ATTACK_BLACKLIST, ATTACK_CMD, ATTACK_DECOY, ATTACK_FLOOD, ATTACK_FORMAT, ATTACK_HEADER, ATTACK_HPP, ATTACK_PATH, ATTACK_SPOOF, ATTACK_SQLI, ATTACK_XSS

# IP
IP_COUNTRY = {}

STOP_THREAD = False

# LOG FUNCTIONS
def make_security_log(application, event_type, request, log_format = 'syslog', user = None, event_details = {}):

    # Get source
    source_ip = request.headers.get('X-Forwarded-For') or request.environ.get('HTTP_X_REAL_IP', request.remote_addr)

    # Get source country
    try:
        country = get_ip_country(source_ip)
    except:
        country = 'Private'

    if log_format.lower() == 'syslog':

        time = datetime.now().strftime(r"%Y/%m/%d %H:%M:%S")

        data = f'[{time}] '
        data += ' - '.join([
            f'"{application}"',
            f'"{event_type}"',
            f'"{source_ip}"',
            f'"{country}"'
        ])

        if event_details.get('location') and event_details.get('payload'):
            location = event_details['location']
            payload = event_details['payload']
            data += ' - '+f'"{location}:{payload}"'

    elif log_format.lower() == 'json':

        data = {
            'time': datetime.now().strftime(r"%Y/%m/%d %H:%M:%S"),
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

def log_worker(input, server, port, format = 'syslog', protocol = 'udp', debug = False):

    webhook = False
    syslog_udp = False
    syslog_tcp = False

    if format.lower() in ['json', 'pcb']:
        server_url = f'{protocol.lower()}://{server}:{port}/logs'
        webhook = True

    elif format.lower() == 'syslog':
        if protocol.lower() == 'udp':
            syslog_udp = True
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif protocol.lower() == 'tcp':
            syslog_tcp = True
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:

        for log_data in iter(input.get, '--STOP--'):

            try:
                if webhook:
                    requests.post(server_url, json=log_data, timeout=3) 
                elif syslog_udp:
                    sock.sendto(log_data.encode(), (server, port))
                elif syslog_tcp:
                    sock.connect((server, port))
                    sock.send(log_data)
                    sock.close()

            except Exception as e:
                if debug: 
                    print(f'Error sending logs : {str(e)}')

    except:
        pass

# BEACON
def beacon_thread(rasp_instance, key):

    counter = 0

    while True :

        time.sleep(1)
        counter += 1
        if STOP_THREAD:
            break
        if counter % rasp_instance.BEACON_DELAY == 0:
            counter = 0
            rasp_instance.send_beacon(key)

    rasp_instance.print_screen('[+] Stopping beacon process', init=True, new_line_up = False)
        
def handle_kb_interrupt(sig, frame):
    global STOP_THREAD
    STOP_THREAD = True
    print('[!] Stopping RASP')
    exit()
    
class FlaskRASP():

    ####################################################
    # GLOBAL VARIABLES
    ####################################################

    # LOGGING
    LOG_QUEUE = None
    LOG_WORKER = None

    # BEACON
    BEACON_THREAD = None

    # KEY
    KEY = None
    
    # Attacks detection
    IP_LIST = {}
    BLACKLIST = {}

    # LOGS
    LOG_ENABLED = False

    # Misc
    INIT_VERBOSE = 0

    ####################################################
    # CONSTRUCTOR & DESTRUCTOR
    ####################################################


    def __init__(self, app, app_name = None, hosts = [], conf = None, key = None, verbose_level = 10, dev = False):

        # Set init verbosity
        if not verbose_level == None:
            self.INIT_VERBOSE = verbose_level

        # Develompent mode
        if dev:
            global PCB_SERVER
            PCB_SERVER = '127.0.0.1:8080'

        # Start display
        self.print_screen(f'### PyRASP v{VERSION} ##########', init=True, new_line_up=True)
        self.print_screen('[+] Starting PyRASP', init=True, new_line_up=False)

        #
        # Check updates
        #

        # self.check_updates()

        #
        # Configuration
        #

        # Load default configuration
        if conf == None and key == None:
            self.print_screen('[!] No configuration provided.', init=True, new_line_up = False)
            self.print_screen('[+] Loading default configuration', init=True, new_line_up = False)
            self.load_config(DEFAULT_CONFIG)

        # Load configuration file
        if conf:
            self.load_file_config(conf)

        # Load from server
        if key:
            if not self.load_cloud_config(key):
                self.print_screen('[!] Could not load configuration. Security NOT enabled.', init=True, new_line_up = True)
                return
            self.KEY = key

        # Default config customization
        if all([
            conf == None,
            key == None,
            not verbose_level == None
        ]):
            self.VERBOSE = verbose_level

        if all([
            conf == None,
            key == None,
            not app_name == None
        ]):
            self.APP_NAME = app_name

        if all([
            conf == None,
            key == None,
            len(hosts)
        ]):
            self.HOSTS = hosts

        # Register security checks
        self.set_before_security_checks(app)
        self.set_after_security_checks(app)

        # Load XSS ML model
        xss_model_loaded = False
        xss_model_file = 'xss_model-'+XSS_MODEL_VERSION

        ## From source
        try:
            self.xss_model = pickle.load(open(xss_model_file,'rb'))
        except:
            pass
        else:
            xss_model_loaded = True

        ## From package
        if not xss_model_loaded:
            try:
                xss_model_file = pkg_resources.resource_filename('pyrasp', 'data/'+xss_model_file)
                self.xss_model = pickle.load(open(xss_model_file,'rb'))
            except:
                pass
            else:
                xss_model_loaded = True

        if not xss_model_loaded:
            self.print_screen('[!] XSS model not loaded', init=False, new_line_up = False)
        else:
            self.print_screen('[+] XSS model loaded', init=True, new_line_up = False)

        # Start logging
        if self.LOG_ENABLED:
            self.start_logging()

        if self.KEY is not None:
            # Set SIGNINT
            signal.signal(signal.SIGINT, handle_kb_interrupt)

            # Start beacon
            self.start_beacon(key)

        self.print_screen('[+] PyRASP succesfully started', init=True)
        self.print_screen('############################', init=True, new_line_down=True)

    def __del__(self):

        if self.KEY is not None:
            if self.BEACON_THREAD and self.BEACON_THREAD.is_alive():
                global STOP_THREAD
                STOP_THREAD = True

        if self.LOG_ENABLED:

            # Clean logging process shutdown
            self.print_screen('[+] Terminating logging process', init=True, new_line_up = False)

            try:
                pass
            except Exception as e:
                self.print_screen('[!] Error terminating logging process', init=True, new_line_up = False)

        return

    ####################################################
    # BEACON & UPDATES
    ####################################################

    def start_beacon(self, key):

        self.print_screen('[+] Starting beacon process', init=True, new_line_up = False)
        self.BEACON_THREAD = Thread(target=beacon_thread, args=(self, key))
        self.BEACON_THREAD.start()
        
    def send_beacon(self, key):

        beacon_url = f'{PCB_PROTOCOL}://{PCB_SERVER}/rasp/beacon'
        data = { 'key': key, 'version': VERSION }

        error = False

        # Send requets to server
        try:
            r = requests.post(beacon_url, json=data)
        except Exception as e:
            self.print_screen(f'[!] Error connecting to cloud server: {str(e)}', init = True)
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
                self.print_screen('[!] Server error')
                error = True

        # Get configuration
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
                server_data = server_response['data']
            except:
                self.print_screen('[!] Corrupted server response')
                error = True

        # Check response status
        if not error:
            if not server_result:
                self.print_screen(f'[!] Error: {server_message}')
                error = True

        # Set configuration
        if not error and server_data.get('config'):
            self.load_config(server_data['config'])

    def check_updates(self):

        self.print_screen('[*] Checking for updates', init = True, new_line_up = True)

        update_url = f'{PCB_PROTOCOL}://{PCB_SERVER}/versions'
        data = { 
            'data_version': DATA_VERSION,
            'xss_model_version': XSS_MODEL_VERSION
        }
        error = False

        # Send requets to server
        try:
            r = requests.post(update_url, json=data)
        except Exception as e:
            self.print_screen(f'[!] Error connecting to cloud server: {str(e)}', init = True)
            error = True

        # Check response status
        if not error:
            if r.status_code == 422:
                self.print_screen('[!] Invalid data sent', init = True)
                error = True

        # Get versions
        if not error:
            try:
                updates = r.json()
                update_data = updates.get('update_data')
                update_xss_model = updates.get('update_xss_model')

            except:
                self.print_screen('[!] Server data error', init = True)
                error = True

        # Update
        if not error:

            # Data
            if update_data:
                self.print_screen('[+] Updating WAF data', init=True)
            else:
                self.print_screen('[=] WAF data is up-to-date', init=True)

            # XSS model
            if update_xss_model:
                self.print_screen('[+] Updating XSS ML model', init=True)
            else:
                self.print_screen('[=] XSS ML model is up-to-date', init=True)

    def say_hello(self):
        print('Hello !!!')

    ####################################################
    # LOGGING
    ####################################################

    def start_logging(self):

        self.print_screen('[+] Starting logging process', init=True, new_line_up = False)
        self.LOG_QUEUE = Queue()
        self.LOG_WORKER = Process(target=log_worker, args=(self.LOG_QUEUE, self.LOG_SERVER, self.LOG_PORT, self.LOG_FORMAT, self.LOG_PROTOCOL ))
        self.LOG_WORKER.start()
        
    def log_security_event(self, event_type, request, user = None, details = {}):

        try:
            security_log = make_security_log(self.APP_NAME, event_type, request, self.LOG_FORMAT, user, details)
        except Exception as e:
            pass
        else:
            self.LOG_QUEUE.put(security_log)

    ####################################################
    # CONFIGURATION
    ####################################################

    def load_cloud_config(self, key):

        result = False

        self.print_screen('[+] Loading configuration from cloud', init = True, new_line_up = False)

        config_url = f'{PCB_PROTOCOL}://{PCB_SERVER}/rasp/connect'
        data = { 'key': key, 'version': VERSION }

        error = False
        
        # Send requets to server
        try:
            r = requests.post(config_url, json=data)
        except Exception as e:
            self.print_screen(f'[!] Error connecting to cloud server: {str(e)}', init = True)
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
                self.print_screen('[!] Server error')
                error = True

        # Get configuration
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
                config = server_response['data']
            except:
                self.print_screen('[!] Corrupted server response')
                error = True

        # Check response status
        if not error:
            if not server_result:
                self.print_screen(f'[!] Error: {server_message}')
                error = True

        # Set configuration
        if not error:
            result = self.load_config(config)

        return result
            
    def load_file_config(self, conf_file):

        self.print_screen(f'[+] Loading configuration from {conf_file}', init = True, new_line_up = False)

        try:
            with open(conf_file) as f:
                config = json.load(f)
        except Exception as e:
            self.print_screen(f'[!] Error reading {conf_file}: {str(e)}', init = True, new_line_up = False)
        else:
            self.load_config(config)
   
    def load_config(self, config):

        for key in config:
            setattr(self, key, config[key])
        
        for key in config:
            self.print_screen(f'[+] {key} => {config[key]}', 100, init=False)        

        return True

    ####################################################
    # SECURITY CHECKS
    ####################################################

    # Incoming request
    def set_before_security_checks(self, app):

        @app.before_request
        def before_request_callback():

            (host, request_method, request_path, source_ip, timestamp) = self.get_params(request)
            (attack_location, attack_payload) = (None, None)

            # Check if source is whitelisted
            whitelist = False

            for whitelist_source in self.WHITELIST:
                if source_ip.startswith(whitelist_source):
                    whitelist = True

            # Not whitelisted, going through security tests
            if not whitelist:

                ignore = False
                attack_id = None
                attack = None

                ### Rules to be applied to all requests

                # Check if source IP is already blacklisted
                if not self.BLACKLIST_OVERRIDE:
                    attack = self.check_blacklist(source_ip, timestamp)
                
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
                        attack = self.check_rule(request, request_method, request_path)

                # Check if path is to be ignored
                if attack == None:
                    if self.check_ignore_path(request_path):
                        ignore = True
                else:
                    ignore = True

                ### Rules to be applied to NOT ignored path
                if not ignore:

                    # Check brute force and flood on vulnerable paths
                    if attack_id == None:
                        if self.SECURITY_CHECKS.get('flood'):
                            attack = self.flood_and_brute_check(request_path, source_ip, timestamp)
                                
                    # Check HTTP Parameter Pollution
                    if attack == None:
                        if self.SECURITY_CHECKS.get('hpp'):
                            attack = self.check_hpp(request)

                    # Get injectable params
                    if attack == None:
                        inject_vectors = self.get_vectors(request)

                    # Check headers
                    if attack == None:
                        if self.SECURITY_CHECKS.get('headers'):
                            attack = self.check_headers(inject_vectors)

                    # Check command injection
                    if attack == None:
                        if self.SECURITY_CHECKS.get('command'):
                            attack = self.check_cmdi(inject_vectors)

                    # Check XSS
                    if attack == None:
                        if self.SECURITY_CHECKS.get('xss'):
                            attack = self.check_xss(inject_vectors)

                    # Check SQL injections
                    if attack == None:
                        if self.SECURITY_CHECKS.get('sqli'):
                            attack = self.check_sqli(inject_vectors)

                # Send attack status in status code for handling by @after_request
                if not attack == None:
                    self.handle_attack(attack, host, request_path, source_ip, timestamp)
                    return self.GTFO_MSG, 1
           
    # Outgoing responses
    def set_after_security_checks(self, app):
        @app.after_request
        def after_request_callback(response):

            (host, request_method, request_path, source_ip, timestamp) = self.get_params(request)

            ignore = False
            response_attack = None
            request_attack = False

            # Get attack from @before_request checks
            if response.status_code == 1:
                request_attack = True
                response.status_code = 403

            # Check if response is error
            if response.status_code < 400:
                ignore = True

            # Check brute force and flood
            if not ignore:
            
                if self.SECURITY_CHECKS.get('flood'):
                    response_attack = self.flood_and_brute_check(request_path, source_ip, timestamp, error=True)
                        
            if response_attack and not request_attack == None:
                self.handle_attack(response_attack, host, request_path, source_ip, timestamp)

            if response_attack or request_attack:
                response.status_code = 403
                response.content = self.GTFO_MSG

            return response

    ####################################################
    # ATTACK HANDLING
    ####################################################

    def handle_attack(self, attack, host, request_path, source_ip, timestamp):

        attack_id = attack['type']
        attack_details = attack.get('details') or {}
        attack_check = ATTACKS_CHECKS[attack_id]

        if not self.BLACKLIST_OVERRIDE:
            self.blacklist_ip(source_ip, timestamp, attack_check)

        
        try:
            self.print_screen(f'[!] {ATTACKS[attack_id]}: {attack["details"]["location"]} -> {attack["details"]["payload"]}')
        except:
            self.print_screen(f'[!] Attack - No details')
        

        if self.LOG_ENABLED:
            self.log_security_event(ATTACKS[attack_id], request, None, attack_details)

    ####################################################
    # SECURITY FUNCTIONS
    ####################################################
        
    # Check if a rule matches the request
    def check_rule(self, request, request_method, request_path):

        attack = None
        rule_exists = False

        rule = request.url_rule
        if rule:
            rule_exists = True

        if not rule_exists:
            attack = {
                'type': ATTACK_PATH,
                'details': {
                    'location': 'request',
                    'payload': request_method + ' ' + request_path
                }
            }

        return attack
    
    # Check floods and brute force attempts
    def flood_and_brute_check(self, request_path, source_ip, timestamp, error = False):

        result = False
        attack = None

        ignore = True
        ratio = self.FLOOD_RATIO
        delay = self.FLOOD_DELAY

        if error:
            ratio = self.ERROR_FLOOD_RATIO
            delay = self.ERROR_FLOOD_DELAY

        ## All requests: check if path is in Brute & Flood vulnerable paths
        for bf_pattern in self.BRUTE_AND_FLOOD_PATHS:
            if re.search(bf_pattern, request_path):
                ignore = False
                break

        ## Error response: all requests to be processed
        if error:
            ignore = False

        ## Request to be processed
        if not ignore:
            # Check if source IP already identified or out of restricted delay
            # If not create / reinitialize structure
            if not source_ip in self.IP_LIST or timestamp > self.IP_LIST[source_ip]['timestamp'] + delay:
                self.IP_LIST[source_ip] = {
                    'timestamp': timestamp,
                    'count': 0
                }
            
            # Increase counters
            self.IP_LIST[source_ip]['count'] += 1

            # Set result if requests count is greater than FLOOD_RATIO
            if self.IP_LIST[source_ip]['count'] > ratio:
                result = True

        if result:
            attack = {
                'type': ATTACK_FLOOD,
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

        if not host in self.HOSTS:
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

        if any([request_path.startswith(decoy_route) for decoy_route in self.DECOY_ROUTES]):
            attack = {
                'type': ATTACK_DECOY,
                'details': {
                    'location': 'path',
                    'payload': request_path
                }
            }

        return attack

    # Check sql injection
    def check_sqli(self, vectors):

        sql_injection = False
        attack = None
        temp_db = sqlite3.connect(":memory:")

        # Get relevant vectors
        for vector_type in SQL_INJECTIONS_VECTORS:

            # Get collected values
            
            for injection in vectors[vector_type]:

                # Identify single word
                if not re.search('[ +\'"(]', injection):
                    continue

                # Test signatures
                for signature in SQL_INJECTIONS_SIGNATURES:
                    if re.search(signature, injection, re.IGNORECASE):
                        sql_injection = True
                        break
                
                # Select proper injected request format
                quotes = ''
                injections_point = SQL_INJECTIONS_POINTS
                
                
                for c in injection:
                    if c == '"':
                        quotes = '"'
                        break
                    if c == "'":
                        quotes = "'"
                        break
                
                # Test valid SQL for injection point
                for injection_point in injections_point:

                    # Add input at injection point with quotes if necessary
                    sql = injection_point.replace('{{vector}}', quotes+injection+quotes)

                    # Add spaces
                    sql = re.sub('\(', ' ( ', sql)
                    sql = re.sub('\)', ' ) ', sql)
                    sql = re.sub('"', ' " ', sql)
                    sql = re.sub("'", " ' ", sql)

                    # Remove comments
                    sql = re.sub('/\*[^*]?\*/', '', sql)
                    sql = re.sub('/\*.*', '', sql)
                    sql = re.sub('--.*', '', sql)
                    sql = re.sub('#.*', '', sql)

                    # Parses request to split stacked requests
                    parsed = sqlparse.split(sql)
                    
                    for statement in parsed:

                        if len(statement):

                            try:
                                temp_db.execute(statement)
                            except Exception as e:
                                if 'no such table' in str(e):
                                    sql_injection = True

                        if sql_injection:
                            break
                            
                    if sql_injection:
                        break
                            
                if sql_injection:
                    break

            if sql_injection:
                break

        if sql_injection:
            attack = {
                'type': ATTACK_SQLI,
                'details': {
                    'location': vector_type,
                    'payload': injection
                }
            }

        return attack

    # Check XSS
    def check_xss(self, vectors):

        xss = False
        attack = None

        # Get relevant vectors
        for vector_type in XSS_VECTORS:

            # Get request values
            for injection in vectors[vector_type]:

                # Requires minimum_length
                if len(injection) > self.MIN_XSS_LEN:

                    xss_probability = self.xss_model.predict_proba([injection.lower()])[0]
                    if xss_probability[1] > self.XSS_PROBA:
                        xss = True
                        break

            if xss:
                break

        if xss:
            attack = {
                'type': ATTACK_XSS,
                'details': {
                    'location': vector_type,
                    'payload': injection
                }
            }

        return attack

    # Check HPP
    def check_hpp(self, request):

        hpp = False
        hpp_param = None
        attack = None

        params = list(request.args.lists()) + list(request.form.lists())

        # Same param in same location (QS or body data)
        for param in params:
            if len(param[1]) > 1:
                hpp = True
                hpp_param = param
                break
        
        # Same param in pultiple locations
        if not hpp:
            wide_params = [ i[0] for i in params]
            if not len(wide_params) == len(set(wide_params)):
                hpp = True
                hpp_param = param

        if hpp:
            attack = {
                'type': ATTACK_HPP,
                'details': {
                    'location': 'param',
                    'payload': hpp_param[0]
                }

            }

        return attack

    # Check command injection
    def check_cmdi(self, vectors):

        command_injection = False
        attack = None

        # Get relevant vectors
        for vector_type in COMMAND_INJECTIONS_VECTORS:

            # Get request values
            for injection in vectors[vector_type]:

                command_pattern = '(?:[&;|]|\$IFS)+\s*(\w+)'
                commands = re.findall(command_pattern, injection) or []

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
    def blacklist_ip(self, source_ip, timestamp, attack_type):

        result = True

        self.BLACKLIST[source_ip] = timestamp

        return result
    
    ####################################################
    # DECOY
    ####################################################

    # Unused for now

    def decoy(self, request):

        return self.GTFO_MSG, 4

    ####################################################
    # UTILS
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
    
    # Get request injection vectors
    def get_vectors(self, request):

        vectors = {
            'path': [],
            'headers_names': [],
            'headers_values': [],
            'cookies': [],
            'user_agent': '',
            'referer': '',
            'qs_variables': [],
            'qs_values': [],
            'post_variables': [],
            'post_values': [],
            'json_keys': [],
            'json_values': [],
            
        }

        # Request path
        request_path = request.path
        for path_element in request_path.split('/'):
            if len(path_element):
                vectors['path'].append(path_element)

        # Query strings
        query_string = request.args.to_dict() or {}
        for qs_variable in query_string:
            qs_value = query_string[qs_variable]
            vectors['qs_variables'].append(qs_variable)
            if len(qs_value):
                vectors['qs_values'].append(qs_value)
            if self.DECODE_B64:
                vectors['qs_values'].extend(self.get_b64_values(qs_value))

        # Posted data
        posted_data = request.form.to_dict() or {}
        for post_variable in posted_data:
            post_value = posted_data[post_variable]
            vectors['post_variables'].append(post_variable)
            if len(post_value):
                vectors['post_values'].append(post_value)
            if self.DECODE_B64:
                vectors['post_values'].extend(self.get_b64_values(post_value))

        # JSON
        try:
            json_data = request.get_json(force=True)
            (json_keys, json_values) = self.analyze_json(json_data)
        except:
            pass
        else:
            vectors['json_keys'] = json_keys
            vectors['json_values'] = json_values

        # Headers
        for header in request.headers:

            # Cookies
            if header[0].lower() == 'cookie':
                cookies = header[1].split(';')
                for cookie in cookies:
                    cookie_parts = cookie.split('=')
                    if len(cookie_parts) == 1:
                        cookie_value = cookie_parts[0].strip()
                    else:
                        cookie_value = cookie_parts[1].strip()
                    vectors['cookies'].append(cookie_value)

            # User Agent
            if header[0].lower() == 'user-agent':
                vectors['user_agent'] = header[1]

            # Refererer
            if header[0].lower() == 'referer':
                vectors['referer'] = header[1]
            
            # Other headers
            else:
                vectors['headers_names'].append(header[0])
                vectors['headers_values'].append(header[1])

        return vectors

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

        if type(structure) is list:
            for el in structure:
                if any( [ type(el) is list, type(el) is dict ]):
                    (new_keys, new_values) = self.analyze_json(el)
                    keys.extend(new_keys)
                    values.extend(new_values)
                else:
                    values.append(str(el))
            return(keys, values)
        elif type(structure) is dict:
            for new_key in structure:
                keys.extend(new_key)
                el = structure[new_key]
                if any( [ type(el) is list, type(el) is dict ]):
                    (new_keys, new_values) = self.analyze_json(el)
                    keys.extend(new_keys)
                    values.extend(new_values)
                else:
                    values.append(str(el))
            return(keys, values)
            
        return (keys, values)

    # Identifies and decode b64 values 
    def get_b64_values(self, param_value):

        b64_values = []

        values = re.findall('(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', param_value)



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

