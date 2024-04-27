VERSION = '0.6.2'

from pprint import pprint
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
import signal
import pkg_resources
import sys
from functools import partial
import psutil
import os
from functools import wraps

# Flask
try:
    from flask import request
    from flask import Response as FlaskResponse
    from flask.wrappers import Response as FlaskResponseType
    from werkzeug.utils import import_string
except:
    pass

# FastAPI
try:
    from fastapi import Request
    from fastapi import Response as FastApiResponse
    from starlette.routing import Match
    from starlette.concurrency import iterate_in_threadpool
except:
    pass

# Django
try:
    from django.conf import settings as django_settings
    from django.http import HttpResponse
    from django.urls import resolve

except:
    pass

# Azure
try:
    import azure.functions as func

except:
    pass

# MULTIPROCESSING - NOT FOR AWS & GCP ENVIRONMENTS
if all([ 
    os.environ.get("AWS_EXECUTION_ENV") is None,
    os.environ.get("K_SERVICE") is None,
]):
    from threading import Thread
    from queue import Queue

# DATA GLOBALS
try:
    from pyrasp.pyrasp_data import DATA_VERSION, XSS_MODEL_VERSION, SQLI_MODEL_VERSION
    from pyrasp.pyrasp_data import CLOUD_FUNCTIONS
    from pyrasp.pyrasp_data import DEFAULT_CONFIG, DEFAULT_SECURITY_CHECKS
    from pyrasp.pyrasp_data import ATTACKS, ATTACKS_CHECKS, ATTACKS_CODES, BRUTE_FORCE_ATTACKS
    from pyrasp.pyrasp_data import SQL_INJECTIONS_POINTS, SQL_INJECTIONS_VECTORS, SQL_INJECTIONS_FP, SQL_QUOTES
    from pyrasp.pyrasp_data import XSS_VECTORS, XSS_NON_ALPHA_PATTERN, NON_ALPHA_PATTERN
    from pyrasp.pyrasp_data import COMMAND_INJECTIONS_VECTORS
    from pyrasp.pyrasp_data import DLP_PATTERNS
    from pyrasp.pyrasp_data import PATTERN_CHECK_FUNCTIONS
    from pyrasp.pyrasp_data import ATTACK_BLACKLIST, ATTACK_CMD, ATTACK_DECOY, ATTACK_FLOOD, ATTACK_FORMAT, ATTACK_HEADER, ATTACK_HPP, ATTACK_PATH, ATTACK_SPOOF, ATTACK_SQLI, ATTACK_XSS, ATTACK_DLP, ATTACK_BRUTE
except:
    from pyrasp_data import DATA_VERSION, XSS_MODEL_VERSION, SQLI_MODEL_VERSION
    from pyrasp_data import CLOUD_FUNCTIONS
    from pyrasp_data import DEFAULT_CONFIG, DEFAULT_SECURITY_CHECKS
    from pyrasp_data import ATTACKS, ATTACKS_CHECKS, ATTACKS_CODES, BRUTE_FORCE_ATTACKS
    from pyrasp_data import SQL_INJECTIONS_POINTS, SQL_INJECTIONS_VECTORS, SQL_INJECTIONS_FP, SQL_QUOTES
    from pyrasp_data import XSS_VECTORS, XSS_NON_ALPHA_PATTERN, NON_ALPHA_PATTERN
    from pyrasp_data import COMMAND_INJECTIONS_VECTORS
    from pyrasp_data import DLP_PATTERNS
    from pyrasp_data import PATTERN_CHECK_FUNCTIONS
    from pyrasp_data import ATTACK_BLACKLIST, ATTACK_CMD, ATTACK_DECOY, ATTACK_FLOOD, ATTACK_FORMAT, ATTACK_HEADER, ATTACK_HPP, ATTACK_PATH, ATTACK_SPOOF, ATTACK_SQLI, ATTACK_XSS, ATTACK_DLP, ATTACK_BRUTE

# IP
IP_COUNTRY = {}
STOP_LOG_THREAD = False
STOP_BEACON_THREAD = False
LOG_QUEUE = None

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

        time = datetime.now().strftime(r"%Y/%m/%d %H:%M:%S")
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

def log_worker(input, server, port, format = 'syslog', protocol = 'udp', path = '', debug = False):

    webhook = False
    syslog_udp = False
    syslog_tcp = False

    if format.lower() in ['json', 'pcb']:
        if not path.startswith('/'):
            path = '/'+path
        server_url = f'{protocol.lower()}://{server}:{port}{path}'
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

def log_thread(rasp_instance, input, server, port, format = 'syslog', protocol = 'udp', path = '', debug = False):

    webhook = False
    syslog_udp = False
    syslog_tcp = False

    if format.lower() in ['json', 'pcb']:
        if not path.startswith('/'):
            path = '/'+path
        server_url = f'{protocol.lower()}://{server}:{port}/logs'
        webhook = True

    elif format.lower() == 'syslog':
        if protocol.lower() == 'udp':
            syslog_udp = True
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif protocol.lower() == 'tcp':
            syslog_tcp = True
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

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
                print(f'[PyRASP] Error sending logs : {str(e)}')

    rasp_instance.print_screen('[+] Logging process stopped', init=True, new_line_up = False)

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
    
class PyRASP():

    ####################################################
    # GLOBAL VARIABLES
    ####################################################

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
    IP_LIST = {}
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
    
    ####################################################
    # CONSTRUCTOR & DESTRUCTOR
    ####################################################

    def __init__(self, app = None, app_name = None, hosts = [], conf = None, key = None, cloud_url = None, verbose_level = 10, dev = False):

        # Set init verbosity
        if not verbose_level == None:
            self.INIT_VERBOSE = verbose_level


        # Development mode
        if dev:
            pass

        # Start display
        self.print_screen(f'### PyRASP v{VERSION} ##########', init=True, new_line_up=True)
        self.print_screen('[+] Starting PyRASP', init=True, new_line_up=False)

        #
        # Get Routes
        #

        self.get_routes(app)

        #
        # Configuration
        #

        self.print_screen('[+] Loading default configuration', init=True, new_line_up = False)
        for config_key in DEFAULT_CONFIG:
            setattr(self, config_key, DEFAULT_CONFIG[config_key])

        # Load from server
        ## Get cloud URL
        if not cloud_url is None:
            self.CLOUD_URL = cloud_url
        else:
            self.CLOUD_URL = os.environ.get('PYRASP_CLOUD_URL')
    
        if not self.CLOUD_URL is None:

            ## Get key
            if key:
                self.KEY = key
            else:
                self.KEY = os.environ.get('PYRASP_KEY')

            if self.KEY is None:
                self.print_screen('[!] Agent key could not be found. Running default configuration.', init=True, new_line_up = True)
            
            if not self.load_cloud_config():
                self.print_screen('[!] Could not load configuration from cloud server. Running default configuration.', init=True, new_line_up = True)

        # Load configuration file
        if not conf is None:
            self.CONF_FILE = conf
        else:
            self.CONF_FILE = os.environ.get('PYRASP_CONF')

        if not self.CONF_FILE is None:
            self.load_file_config(self.CONF_FILE)

        # Default config customization from 
        if all([
            self.CONF_FILE == None,
            self.KEY == None,
            not verbose_level == None
        ]):
            self.VERBOSE = verbose_level

        if all([
            self.CONF_FILE == None,
            self.KEY == None,
            not app_name == None
        ]):
            self.APP_NAME = app_name

        if all([
            self.CONF_FILE == None,
            self.KEY== None,
            len(hosts)
        ]):
            self.HOSTS = hosts

        # Register security checks
        if not app is None:
            self.register_security_checks(app)


        ## XSS & SQLI models loaded only if enabled in configuration
        if self.SECURITY_CHECKS.get('xss'):
            # Load XSS ML model
            xss_model_loaded = False
            if not dev:
                xss_model_file = 'xss_model-'+XSS_MODEL_VERSION
            else:
                xss_model_file = 'xss_model-dev'

            ## From source
            try:
                self.xss_model = pickle.load(open('ml-engines/'+xss_model_file,'rb'))
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

        if self.SECURITY_CHECKS.get('sqli'):
            # Load SQLI ML model
            sqli_model_loaded = False
            if not dev:
                sqli_model_file = 'sqli_model-'+SQLI_MODEL_VERSION
            else:
                sqli_model_file = 'sqli_model-dev'

            ## From source
            try:
                self.sqli_model = pickle.load(open('ml-engines/'+sqli_model_file,'rb'))
            except:
                pass
            else:
                sqli_model_loaded = True

            ## From package
            if not sqli_model_loaded:
                try:
                    sqli_model_file = pkg_resources.resource_filename('pyrasp', 'data/'+sqli_model_file)
                    self.sqli_model = pickle.load(open(sqli_model_file,'rb'))
                except Exception as e:
                    pass
                else:
                    sqli_model_loaded = True

            if not sqli_model_loaded:
                self.print_screen('[!] SQLI model not loaded', init=False, new_line_up = False)
            else:
                self.print_screen('[+] SQLI model loaded', init=True, new_line_up = False)


        # AWS, GCP & Azure
        if self.PLATFORM in CLOUD_FUNCTIONS:
            pass

        # Other environments
        else:   
            from threading import Thread
            from queue import Queue

            # Start logging thread
            if self.LOG_ENABLED:
                self.start_logging()

            # Start beacon thread
            if self.BEACON:
                self.start_beacon()

        self.print_screen('[+] PyRASP succesfully started', init=True)
        self.print_screen('############################', init=True, new_line_down=True)

    def __del__(self):

        if not self.PLATFORM in CLOUD_FUNCTIONS:

            if self.BEACON:
                global STOP_BEACON_THREAD
                STOP_BEACON_THREAD = True

            if self.LOG_ENABLED:
                self.LOG_QUEUE.put('--STOP--')

        return
    
    def register_security_checks(self, app):
        pass

    ####################################################
    # BEACON & UPDATES
    ####################################################

    def start_beacon(self):

        self.print_screen('[+] Starting beacon process', init=True, new_line_up = False)
        self.BEACON_THREAD = Thread(target=beacon_thread, args=(self, ))
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
            r = requests.post(beacon_url, json=data)
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
            new_config = { 'config': server_data['config'] }
            config_changes = self.check_config_change(server_data['config'])
            self.load_config(new_config)

        # Restart services
        if not error and not self.PLATFORM in CLOUD_FUNCTIONS:
            if config_changes['logs']:
                self.start_logging(restart = True) 
            if config_changes['beacon']:
                pass

    def check_config_change(self, new_config):

        config_changes = {
            'logs': False,
            'beacon': False
        }

        # Check logs config change
        if any([
            not new_config['LOG_FORMAT'] == self.LOG_FORMAT,
            not new_config['LOG_PROTOCOL'] == self.LOG_PROTOCOL,
            not new_config['LOG_SERVER'] == self.LOG_SERVER,
            not new_config['LOG_PORT'] == self.LOG_PORT,
            not new_config['LOG_PATH'] == self.LOG_PATH
        ]):
            config_changes['logs'] = True

        # Check beacon config change
        if any([
            not new_config['BEACON_DELAY'] == self.BEACON_DELAY,
            not new_config['BEACON_URL'] == self.BEACON_URL
        ]):
            config_changes['beacon'] = True


        return config_changes

    ####################################################
    # LOGGING
    ####################################################

    def start_logging(self, restart = False):

        if restart:
            self.LOG_QUEUE.put('--STOP--')
            while self.LOG_THREAD.is_alive():
                time.sleep(1)

        self.print_screen('[+] Starting logging process', init=True, new_line_up = False)
        self.LOG_QUEUE = Queue()
        self.LOG_THREAD = Thread(target=log_thread, args=(self, self.LOG_QUEUE, self.LOG_SERVER, self.LOG_PORT, self.LOG_FORMAT, self.LOG_PROTOCOL, self.LOG_PATH ))
        self.LOG_THREAD.start()
        
    def log_security_event(self, event_type, source_ip, user = None, details = {}):

        try:
            security_log = make_security_log(self.APP_NAME, event_type, source_ip, self.LOG_FORMAT, user, details, self.RESOLVE_COUNTRY)
        except:
            pass
        else:
            self.LOG_QUEUE.put(security_log)

    ####################################################
    # ROUTES
    ####################################################
            
    def get_routes(self, app):
        pass

    ####################################################
    # CONFIGURATION
    ####################################################

    def load_cloud_config(self):

        result = False

        self.print_screen(f'[+] Loading configuration from {self.CLOUD_URL}', init = True, new_line_up = False)

        #config_url = f'{self.cloud_protocol}://{self.cloud_server}:{self.cloud_port}/rasp/connect'
        data = { 'key': self.KEY, 'version': VERSION, 'platform': self.PLATFORM }

        error = False
        
        # Send requets to server
        try:
            r = requests.post(self.CLOUD_URL, json=data)
        except Exception as e:
            self.print_screen('[PyRASP] Error connecting to cloud server')
            #self.print_screen(f'[!] Error connecting to cloud server: {str(e)}', init = True)
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

        # Load parameters
        config_params = config.get('config') or config

        for key in config_params:
            setattr(self, key, config_params[key])

        # Setting defautl security checks
        for security_check in DEFAULT_SECURITY_CHECKS:
            if config_params['SECURITY_CHECKS'].get(security_check) == None:
                config_params['SECURITY_CHECKS'][security_check] = DEFAULT_SECURITY_CHECKS[security_check]
        
        for key in config_params:
            self.print_screen(f'[+] {key} => {config_params[key]}', 100, init=False)    

        # Load blacklist
        config_blacklist = config.get('blacklist')

        if config_blacklist:
            self.BLACKLIST = config_blacklist

        return True

    ####################################################
    # ATTACK HANDLING
    ####################################################

    def handle_attack(self, attack, host, request_path, source_ip, timestamp):

        attack_id = attack['type']
        attack_check = ATTACKS_CHECKS[attack_id]
        attack_details = attack.get('details') or {}
        action = None

        # Generic case
        if not attack_id == 0:
            action = self.SECURITY_CHECKS[attack_check] 
        # Blacklist
        else:
            action = 2

        attack_details['action'] = action
        if ATTACKS_CODES.get(attack_id):
            attack_details['codes'] = ATTACKS_CODES[attack_id]

        if not self.BLACKLIST_OVERRIDE and action == 2:
            self.blacklist_ip(source_ip, timestamp, attack_check)


        try:
            self.print_screen(f'[!] {ATTACKS[attack_id]}: {attack["details"]["location"]} -> {attack["details"]["payload"]}')
        except:
            self.print_screen(f'[!] Attack - No details')
    
        if self.LOG_ENABLED:
            self.log_security_event(attack_check, source_ip, None, attack_details)

    ####################################################
    # CHECKS CONTROL
    ####################################################

    # Inbound attacks
    def check_inbound_attacks(self, host, request_method, request_path, source_ip, timestamp, request, inject_vectors = None):

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
                response = self.make_attack_response()
            self.REQUESTS['attacks'] += 1

        elif response.status_code == 200:
            self.REQUESTS['success'] += 1

        else:
            self.REQUESTS['errors'] += 1

        if self.CHANGE_SERVER:
            response = self.change_server(response)

        return response

    ####################################################
    # SECURITY FUNCTIONS
    ####################################################

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
            attack_type = ATTACK_BRUTE

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
        temp_db = sqlite3.connect(":memory:")

        # Get relevant vectors
        for vector_type in SQL_INJECTIONS_VECTORS:

            # Get collected values
            
            for injection in vectors[vector_type]:

                # Identify single word
                if not re.search('[ +\'"(]', injection):
                    continue

                # Identify only alphanum, space
                if re.search('^[a-zA-Z0-9 ]+$', injection) and not re.search('\snull\s', injection):
                    continue

                # Identify known FP
                fp = False
                for fp_pattern in SQL_INJECTIONS_FP:
                    if re.search(fp_pattern, injection):
                        fp = True
                        break
                if fp:
                    continue

                # Select proper injected request format
                sql_quotes = ['']
                injections_point = SQL_INJECTIONS_POINTS
                              
                '''
                for c in injection:
                    if c == '"':
                        quotes = '"'
                        break
                    if c == "'":
                        quotes = "'"
                        break
                '''

                for c in injection:
                    if c in SQL_QUOTES and not c in sql_quotes:
                        sql_quotes.append(c)
                
                # Test valid SQL for injection point
                for injection_point in injections_point:

                    for quotes in sql_quotes:

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

                if len(injection) < self.MIN_SQLI_LEN:
                    continue

                # Machine Learning check
                if not sql_injection:
                    sqli_probability = self.sqli_model.predict_proba([injection.lower()])[0]
                    if sqli_probability[1] > self.SQLI_PROBA:
                        sql_injection = True
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

                    if re.match(NON_ALPHA_PATTERN, injection) or len(re.findall(XSS_NON_ALPHA_PATTERN, injection)) > 8:
                        xss = True
                        break

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

    # Check response content for DLP
    def check_dlp(self, content):

        attack = None
        payload = None

        if payload == None and self.DLP_PHONE_NUMBERS:
            if self.check_dlp_patterns('phone', content):
                payload = 'Phone Number'

        if payload == None and self.DLP_CC_NUMBERS:
            if self.check_dlp_patterns('cc', content):
                payload = 'Credit Card'

        if payload == None and self.DLP_PRIVATE_KEYS:
            if self.check_dlp_patterns('key', content):
                payload = 'Private Key'

        if payload == None and self.DLP_HASHES:
            if self.check_dlp_patterns('hash', content):
                payload = 'Private Key'

        if payload == None and self.DLP_WINDOWS_CREDS:
            if self.check_dlp_patterns('windows', content):
                payload = 'Windows Credentials'

        if payload == None and self.DLP_LINUX_CREDS:
            if self.check_dlp_patterns('linux', content):
                payload = 'Linux Credentials'

        if payload:
            attack = {
                'type': ATTACK_DLP,
                'details': {
                    'location': 'content',
                    'payload': payload
                }
            }

        return attack
    
    def check_dlp_patterns(self, patterns, content):

        result = False

        for pattern in DLP_PATTERNS[patterns]:
            if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                result = True
                break

        return result
        
    ####################################################
    # RESPONSE PROCESSING
    ####################################################

    def change_server(self, response):

        response.headers['Server'] = self.SERVER_HEADER

        return response
    
    def make_attack_response(self):

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
            'json_values': [],
            
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
            vectors['qs_variables'].extend(qs_variable)
            for qs_value in qs_values:
                if len(qs_value):
                    vectors['qs_values'].extend(self.decode_value(qs_value))

        # Posted data
        posted_data = self.get_posted_data(request)
        for post_variable in posted_data:
            post_values = posted_data[post_variable]
            vectors['post_variables'].extend(post_variable)
            for post_value in post_values:
                if len(post_value):
                    vectors['post_values'].extend(self.decode_value(post_value))

        # JSON
        (json_keys, json_values) = self.get_json_data(request)
        
        vectors['json_keys'] = json_keys

        for json_value in json_values:
            vectors['json_values'].extend(self.decode_value(json_value))    

        # Headers
        headers = self.get_request_headers(request)
        for header in headers:

            # Cookies
            if header.lower() == 'cookie':
                cookies = headers[header].split(';')
                for cookie in cookies:
                    cookie_parts = cookie.split('=')
                    if len(cookie_parts) == 1:
                        cookie_value = cookie_parts[0].strip()
                    else:
                        cookie_value = cookie_parts[1].strip()
                    vectors['cookies'].extend(self.decode_value(cookie_value))
                
            # User Agent
            elif header.lower() == 'user-agent':
                vectors['user_agent'] = [ headers[header] ]

            # Refererer
            elif header.lower() == 'referer':
                vectors['referer'] = [ headers[header] ]
            
            # Other headers
            else:
                vectors['headers_names'].append(header)
                vectors['headers_values'].append(headers[header])

        return vectors
    
    # Remove exceptions from vectors
    def remove_exceptions(self, inject_vectors):
                    
        for vector in inject_vectors:

            inject_payloads = inject_vectors[vector]

            for payload in inject_payloads:

                is_exception = False

                for exception in self.EXCEPTIONS:

                    if type(exception) == list:
                        pattern = exception[0]
                        match_type = exception[1]
                        if not match_type in PATTERN_CHECK_FUNCTIONS:
                            match_type = 'match'
                    else:
                        pattern = exception
                        match_type = 'match'

                    if self.check_pattern(payload, pattern, match_type):
                        is_exception = True
                        break
                
                if is_exception:
                    inject_payloads.remove(payload)

        return inject_vectors

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

    # Decode
    def decode_value(self, value, decode = True, b64 = True):

        decoded_variables = [ value ]

        if decode:
            try:
                decoded = value.encode().decode('unicode_escape')
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

class FlaskRASP(PyRASP):

    CURRENT_ATTACKS = {}

    def __init__(self, app, app_name=None, hosts=[], conf=None, key=None, cloud_url=None,verbose_level=10, dev=False):
        self.PLATFORM = 'Flask'
        super().__init__(app, app_name, hosts, conf, key, cloud_url, verbose_level, dev)

        if self.LOG_ENABLED or self.BEACON:
            signal.signal(signal.SIGINT, partial(handle_kb_interrupt, self))
            
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
            
            attack = self.check_inbound_attacks(host, request_method, request_path, source_ip, timestamp, request)

            # Send attack status in status code for handling by @after_request
            if not attack == None:
                attack_id = '::'.join([host, request_method, request_path, source_ip])
                self.CURRENT_ATTACKS[attack_id] = attack

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
            attack_id = '::'.join([host, request_method, request_path, source_ip])
            current_attack = self.CURRENT_ATTACKS.get(attack_id)
            if current_attack:
                request_attack = current_attack
                del self.CURRENT_ATTACKS[attack_id]

            status_code = response.status_code
            inbound_attack_type = current_attack['type'] if current_attack else None

            # Check brute force and flood
            try:
                response_content =  response.get_data(True)
            except:
                pass
            else:
                response_attack = self.check_outbound_attacks(response_content, request_path, source_ip, timestamp, status_code, inbound_attack_type)
                
            # Set response   
            if response_attack:
                security_check = ATTACKS_CHECKS[response_attack['type']]
            elif request_attack:
                security_check = ATTACKS_CHECKS[request_attack['type']]
            
            if response_attack:
                self.handle_attack(response_attack, host, request_path, source_ip, timestamp)
            elif request_attack:
                self.handle_attack(request_attack, host, request_path, source_ip, timestamp)

            # Check log only
            if security_check and self.SECURITY_CHECKS.get(security_check) == 3:
                log_only = True

            # Process response
            response = self.process_response(response, response_attack or request_attack, log_only = log_only)

            return response

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
    
    def make_attack_response(self):

        response = FlaskResponse()
        response.set_data(self.GTFO_MSG)
        response.status_code = self.DENY_STATUS_CODE

        return response

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

        posted_data = {}

        posted_data_full = request.get_data().decode()

        posted_data_parts = posted_data_full.split('&')

        for posted_data_part in posted_data_parts:
            posted_data_tuple = posted_data_part.split('=')
            if len(posted_data_tuple) == 2:
                post_variable = posted_data_tuple[0]
                post_value = posted_data_tuple[1]

                if not post_variable in posted_data:
                    posted_data[post_variable] = []

                posted_data[post_variable].append(post_value)

        return posted_data

    def get_json_data(self, request):

        json_keys = []
        json_values = []

        try:
            json_data = request.get_json(force=True)
            (json_keys, json_values) = self.analyze_json(json_data)
        except:
            pass

        return (json_keys, json_values)
    
    def get_request_headers(self, request):

        headers = {}

        for header_tuple in request.headers:
            headers[header_tuple[0]] = header_tuple[1]

        return headers

class FastApiRASP(PyRASP):

    def __init__(self, app, app_name=None, hosts=[], conf=None, key=None, cloud_url=None, verbose_level=10, dev=False):
        self.PLATFORM = 'FastAPI'

        # Init
        super().__init__(app, app_name, hosts, conf, key, cloud_url, verbose_level, dev)

        if self.LOG_ENABLED:
            @app.on_event("shutdown")
            async def shutdown_event():
                if self.BEACON:
                    global STOP_BEACON_THREAD
                    STOP_BEACON_THREAD = True

                if self.LOG_ENABLED:
                    self.LOG_QUEUE.put('--STOP--')
                
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

            # Get vectors - need to do it here as async
            vectors = await self.get_vectors(request) 

            # Check inboud attacks
            inbound_attack = self.check_inbound_attacks(host, request_method, request_path, source_ip, timestamp, request, vectors)
              
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
                
                response_body = [chunk async for chunk in response.body_iterator]
                response.body_iterator = iterate_in_threadpool(iter(response_body))
                response_content = response_body[0].decode()
                
            outbound_attack = self.check_outbound_attacks(response_content, request_path, source_ip, timestamp, status_code, inbound_attack_type)

            # Set response   
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
    
    def make_attack_response(self):

        response = FastApiResponse(content = self.GTFO_MSG, status_code= self.DENY_STATUS_CODE)
        
        return response


    ####################################################
    # PARAMS & VECTORS
    ####################################################
    
    # Get request params
    def get_params(self, request):
        request_path = request.url.path
        request_method = request.method
        source_ip_list = request.headers.get('HTTP_X_FORWARDED_FOR') or request.client.host
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
    
    def get_posted_data(self, request):

        posted_data = {}

        return posted_data

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

        headers = request.headers

        return headers

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
            vectors['qs_variables'].extend(qs_variable)
            for qs_value in qs_values:
                if len(qs_value):
                    vectors['qs_values'].extend(self.decode_value(qs_value))

        # Posted data
        posted_data = self.get_posted_data(request)
        for post_variable in posted_data:
            post_value = posted_data[post_variable]
            vectors['post_variables'].append(post_variable)
            if len(post_value):
                vectors['post_values'].extend(self.decode_value(post_value))

        # JSON
        (json_keys, json_values) = await self.get_json_data(request)
        
        vectors['json_keys'] = json_keys

        for json_value in json_values:
            vectors['json_values'].extend(self.decode_value(json_value))    

        # Headers
        headers = self.get_request_headers(request)
        for header in headers:

            # Cookies
            if header.lower() == 'cookie':
                cookies = headers[header].split(';')
                for cookie in cookies:
                    cookie_parts = cookie.split('=')
                    if len(cookie_parts) == 1:
                        cookie_value = cookie_parts[0].strip()
                    else:
                        cookie_value = cookie_parts[1].strip()
                    vectors['cookies'].extend(self.decode_value(cookie_value))
                
            # User Agent
            elif header.lower() == 'user-agent':
                vectors['user_agent'] = [ headers[header] ]

            # Refererer
            elif header.lower() == 'referer':
                vectors['referer'] = [ headers[header] ]
            
            # Other headers
            else:
                vectors['headers_names'].append(header)
                vectors['headers_values'].append(headers[header])

        return vectors

class DjangoRASP(PyRASP):

    def __init__(self, get_response):

        self.PLATFORM = 'Django'
        self.get_response = get_response

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

        # Init
        super().__init__(None, None, [], conf, key, cloud_url, 10, False)

    def __call__(self, request):

        inbound_attack = None
        outbound_attack = None
        error = False
        status_code = 200
        log_only = False
        security_check = None

        # Get Main params
        (host, request_method, request_path, source_ip, timestamp) = self.get_params(request)

        # Check inboud attacks
        inbound_attack = self.check_inbound_attacks(host, request_method, request_path, source_ip, timestamp, request)

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
            response_content = response.content.decode()

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

    def make_attack_response(self):

        response = HttpResponse()
        response.content = self.GTFO_MSG
        response.status_code = self.DENY_STATUS_CODE

        return response

    ####################################################
    # UTILS
    ####################################################
    
    def get_params(self, request):

        request_path = request.path
        request_method = request.method
        source_ip_list = request.headers.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
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

        try:
            json_data = request.body
            (json_keys, json_values) = self.analyze_json(json_data)
        except:
            pass

        return (json_keys, json_values)
    
    def get_request_headers(self, request):

        headers = request.headers

        return headers
    
class LambdaRASP(PyRASP):

    LAST_BEACON = time.time()

    def __init__(self, app=None, app_name=None, hosts=[], conf=None, key=None, cloud_url=None, verbose_level=10, dev=False):
        self.PLATFORM = 'AWS Lambda'
        super().__init__(app, app_name, hosts, conf, key, cloud_url, verbose_level, dev)
        if self.BEACON:
            self.send_beacon()

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
            time_now = time.time()
            if self.BEACON and time_now > self.LAST_BEACON + self.BEACON_DELAY:
                self.send_beacon()
                self.LAST_BEACON = time_now

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

            status_code = response.get('statusCode')
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
        
        webhook = False
        syslog_udp = False
        syslog_tcp = False

        if self.LOG_FORMAT.lower() in ['json', 'pcb']:
            path = self.LOG_PATH
            if not path.startswith('/'):
                path = '/'+path
            server_url = f'{self.LOG_PROTOCOL.lower()}://{self.LOG_SERVER}:{self.LOG_PORT}{path}'
            webhook = True

        elif self.LOG_FORMAT.lower() == 'syslog':
            if self.LOG_PROTOCOL.lower() == 'udp':
                syslog_udp = True
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            elif self.LOG_PROTOCOL.lower() == 'tcp':
                syslog_tcp = True
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            if webhook:
                requests.post(server_url, json=log_data, timeout=1) 
            elif syslog_udp:
                sock.sendto(log_data.encode(), (self.LOG_SERVER, self.LOG_PORT))
            elif syslog_tcp:
                sock.connect((self.LOG_SERVER, self.LOG_PORT))
                sock.settimeout(1)
                sock.send(log_data)
                sock.close()

        except:
            pass

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
            'body': json.dumps(self.GTFO_MSG)
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

        posted_data_full = request.get('body') or ''

        posted_data_parts = posted_data_full.split('&')

        for posted_data_part in posted_data_parts:
            posted_data_tuple = posted_data_part.split('=')
            if len(posted_data_tuple) == 2:
                post_variable = posted_data_tuple[0]
                post_value = posted_data_tuple[1]

                if not post_variable in posted_data:
                    posted_data[post_variable] = []

                posted_data[post_variable].append(post_value)

        return posted_data
    
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
            json_data = json.loads(request['body'])
            (json_keys, json_values) = self.analyze_json(json_data)
        except:
            pass

        return (json_keys, json_values)
    
    def get_request_headers(self, request):

        headers = request.get('headers') or {}

        return headers
        
class GcpRASP(FlaskRASP):

    LAST_BEACON = time.time()

    def __init__(self, app=None, app_name=None, hosts=[], conf=None, key=None, cloud_url=None, verbose_level=10, dev=False):
        self.PLATFORM = 'Google Cloud Function'
        super(FlaskRASP, self).__init__(app, app_name, hosts, conf, key, cloud_url, verbose_level, dev)
        if self.BEACON:
            self.send_beacon()


    ####################################################
    # CHECKS CONTROL
    ####################################################

    # GCP handler wrapper
    def register(self, f):
    
        @wraps(f)
        def decorator(request):

            # Sending beacons to get configuration and blacklist updates
            time_now = time.time()
            if self.BEACON and time_now > self.LAST_BEACON + self.BEACON_DELAY:
                self.send_beacon()
                self.LAST_BEACON = time_now

            (host, request_method, request_path, source_ip, timestamp) = self.get_params(request)

            # Analyze request
            inbound_attack = None
            outbound_attack = None
            log_only = False
            security_check = None
            status_code = 200
            response = None

            inbound_attack = self.check_inbound_attacks(host, request_method, request_path, source_ip, timestamp, request)

            if inbound_attack:
                security_check = ATTACKS_CHECKS[inbound_attack['type']]

            if not inbound_attack or self.SECURITY_CHECKS.get(security_check) == 3:
                response = f(request)

            (response_content, status_code) = self.get_response_data(response) or None
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
    # RESPONSE PROCESSING
    ####################################################

    # Alter response
    def process_response(self, response, attack = None, log_only = True):

        status_code = self.get_response_data(response)[1]

        if attack:
            if not log_only:
                response = self.make_attack_response()
            self.REQUESTS['attacks'] += 1

        elif status_code == 200:
            self.REQUESTS['success'] += 1

        else:
            self.REQUESTS['errors'] += 1

        return response
    
    def make_attack_response(self):

        response = FlaskResponse()
        response.set_data(self.GTFO_MSG)
        response.status_code = self.DENY_STATUS_CODE

        return response

    def get_response_data(self, response):

        if type(response) == FlaskResponseType:
            status_code = response.status_code
            content = response.get_data(True)

        elif type(response) == tuple:
            content = response[0]
            if len(response) == 2:
                status_code = response[1]
            else:
                status_code = 200

        else:
            content = response
            status_code = 200

        return (content, status_code)
    
    ####################################################
    # LOGGING
    ####################################################

    def log_security_event(self, event_type, source_ip, user = None, details = {}):

        log_data = make_security_log(self.APP_NAME, event_type, source_ip, self.LOG_FORMAT, user, details, False)
        
        webhook = False
        syslog_udp = False
        syslog_tcp = False

        if self.LOG_FORMAT.lower() in ['json', 'pcb']:
            path = self.LOG_PATH
            if not path.startswith('/'):
                path = '/'+path
            server_url = f'{self.LOG_PROTOCOL.lower()}://{self.LOG_SERVER}:{self.LOG_PORT}{path}'
            webhook = True

        elif self.LOG_FORMAT.lower() == 'syslog':
            if self.LOG_PROTOCOL.lower() == 'udp':
                syslog_udp = True
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            elif self.LOG_PROTOCOL.lower() == 'tcp':
                syslog_tcp = True
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            if webhook:
                requests.post(server_url, json=log_data, timeout=1) 
            elif syslog_udp:
                sock.sendto(log_data.encode(), (self.LOG_SERVER, self.LOG_PORT))
            elif syslog_tcp:
                sock.connect((self.LOG_SERVER, self.LOG_PORT))
                sock.settimeout(1)
                sock.send(log_data)
                sock.close()

        except:
            pass

class AzureRASP(PyRASP):

    LAST_BEACON = time.time()

    def __init__(self, app=None, app_name=None, hosts=[], conf=None, key=None, cloud_url=None, verbose_level=10, dev=False):
        self.PLATFORM = 'Azure Function'
        super().__init__(app, app_name, hosts, conf, key, cloud_url, verbose_level, dev)

    ####################################################
    # CHECKS CONTROL
    ####################################################

    # Azure Function handler wrapper
    def register(self, f):
    
        @wraps(f)
        def decorator(req):

            request = req

            # Sending beacons to get configuration and blacklist updates
            time_now = time.time()
            if self.BEACON and time_now > self.LAST_BEACON + self.BEACON_DELAY:
                self.send_beacon()
                self.LAST_BEACON = time_now

            (host, request_method, request_path, source_ip, timestamp) = self.get_params(request)

            # Analyze request
            inbound_attack = None
            outbound_attack = None
            log_only = False
            security_check = None
            status_code = 200
            response = func.HttpResponse()

            inbound_attack = self.check_inbound_attacks(host, request_method, request_path, source_ip, timestamp, request)

            if inbound_attack:
                security_check = ATTACKS_CHECKS[inbound_attack['type']]

            if not inbound_attack or self.SECURITY_CHECKS.get(security_check) == 3:
                response = f(req)

            response_content = response.get_body().decode() or ''
            status_code = response.status_code
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
    # RESPONSE PROCESSING
    ####################################################

    # Alter response
    def process_response(self, response, attack = None, log_only = True):

        status_code = response.status_code

        if attack:
            if not log_only:
                response = self.make_attack_response()
            self.REQUESTS['attacks'] += 1

        elif status_code == 200:
            self.REQUESTS['success'] += 1

        else:
            self.REQUESTS['errors'] += 1

        return response
    
    def make_attack_response(self):

        response = func.HttpResponse(self.GTFO_MSG, status_code=self.DENY_STATUS_CODE)

        return response

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
    
    def get_query_string(self, request):

        query_string_list = dict(request.params)

        query_string = {}
        for qs_variable in query_string_list:
            qs_value = query_string_list[qs_variable]
            if not qs_variable in query_string:
                query_string[qs_variable] = []
            query_string[qs_variable].append(qs_value)

        return query_string
    
    def get_posted_data(self, request):

        posted_data = {}

        posted_data_full = request.get_body().decode() or ''

        posted_data_parts = posted_data_full.split('&')

        for posted_data_part in posted_data_parts:
            posted_data_tuple = posted_data_part.split('=')
            if len(posted_data_tuple) == 2:
                post_variable = posted_data_tuple[0]
                post_value = posted_data_tuple[1]

                if not post_variable in posted_data:
                    posted_data[post_variable] = []

                posted_data[post_variable].append(post_value)

        return posted_data
    
    def get_request_path(self, request):
        
        headers = dict(request.headers)

        request_path = headers.get('x-original-url') if headers.get('x-original-url') else '/'

        return request_path
    
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

    ####################################################
    # LOGGING
    ####################################################

    def log_security_event(self, event_type, source_ip, user = None, details = {}):

        log_data = make_security_log(self.APP_NAME, event_type, source_ip, self.LOG_FORMAT, user, details, False)
        
        webhook = False
        syslog_udp = False
        syslog_tcp = False

        if self.LOG_FORMAT.lower() in ['json', 'pcb']:
            path = self.LOG_PATH
            if not path.startswith('/'):
                path = '/'+path
            server_url = f'{self.LOG_PROTOCOL.lower()}://{self.LOG_SERVER}:{self.LOG_PORT}{path}'
            webhook = True

        elif self.LOG_FORMAT.lower() == 'syslog':
            if self.LOG_PROTOCOL.lower() == 'udp':
                syslog_udp = True
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            elif self.LOG_PROTOCOL.lower() == 'tcp':
                syslog_tcp = True
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            if webhook:
                requests.post(server_url, json=log_data, timeout=1) 
            elif syslog_udp:
                sock.sendto(log_data.encode(), (self.LOG_SERVER, self.LOG_PORT))
            elif syslog_tcp:
                sock.connect((self.LOG_SERVER, self.LOG_PORT))
                sock.settimeout(1)
                sock.send(log_data)
                sock.close()

        except:
            pass

    

