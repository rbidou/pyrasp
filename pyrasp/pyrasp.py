VERSION = '0.4.4'

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

# Flask
try:
    from flask import request
    from flask import Response as FlaskResponse
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

# MULTIPROCESSING
from threading import Thread
from queue import Queue

# DATA GLOBALS
try:
    from pyrasp.pyrasp_data import DATA_VERSION, XSS_MODEL_VERSION, SQLI_MODEL_VERSION
    from pyrasp.pyrasp_data import PCB_SERVER, PCB_PROTOCOL
    from pyrasp.pyrasp_data import DEFAULT_CONFIG
    from pyrasp.pyrasp_data import ATTACKS, ATTACKS_CHECKS
    from pyrasp.pyrasp_data import SQL_INJECTIONS_POINTS, SQL_INJECTIONS_VECTORS, SQL_INJECTIONS_FP
    from pyrasp.pyrasp_data import XSS_VECTORS
    from pyrasp.pyrasp_data import COMMAND_INJECTIONS_VECTORS
    from pyrasp.pyrasp_data import DLP_PATTERNS
    from pyrasp.pyrasp_data import ATTACK_BLACKLIST, ATTACK_CMD, ATTACK_DECOY, ATTACK_FLOOD, ATTACK_FORMAT, ATTACK_HEADER, ATTACK_HPP, ATTACK_PATH, ATTACK_SPOOF, ATTACK_SQLI, ATTACK_XSS, ATTACK_DLP
except:
    from pyrasp_data import DATA_VERSION, XSS_MODEL_VERSION, SQLI_MODEL_VERSION
    from pyrasp_data import PCB_SERVER, PCB_PROTOCOL
    from pyrasp_data import DEFAULT_CONFIG
    from pyrasp_data import ATTACKS, ATTACKS_CHECKS
    from pyrasp_data import SQL_INJECTIONS_POINTS, SQL_INJECTIONS_VECTORS, SQL_INJECTIONS_FP
    from pyrasp_data import XSS_VECTORS
    from pyrasp_data import COMMAND_INJECTIONS_VECTORS
    from pyrasp_data import DLP_PATTERNS
    from pyrasp_data import ATTACK_BLACKLIST, ATTACK_CMD, ATTACK_DECOY, ATTACK_FLOOD, ATTACK_FORMAT, ATTACK_HEADER, ATTACK_HPP, ATTACK_PATH, ATTACK_SPOOF, ATTACK_SQLI, ATTACK_XSS, ATTACK_DLP

# IP
IP_COUNTRY = {}
STOP_THREAD = False
LOG_QUEUE = None

# LOG FUNCTIONS
def make_security_log(application, event_type, source_ip, log_format = 'syslog', user = None, event_details = {}):

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

def log_thread(input, server, port, format = 'syslog', protocol = 'udp', debug = False):

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

    while True:

        log_data = input.get()

        if log_data == '--STOP--':
            break

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

# BEACON
def beacon_thread(rasp_instance, key):

    counter = 0

    while True :

        try:

            time.sleep(1)
            counter += 1

            if STOP_THREAD:
                break

            if counter % rasp_instance.BEACON_DELAY == 0:
                counter = 0
                rasp_instance.send_beacon(key)

        except KeyboardInterrupt:
            break

    rasp_instance.print_screen('[+] Stopping beacon process', init=True, new_line_up = False)
        
def handle_kb_interrupt(queue, sig, frame):
    global STOP_THREAD
    STOP_THREAD = True
    queue.put('--STOP--')
    sys.exit()
    
class PyRASP():

    ####################################################
    # GLOBAL VARIABLES
    ####################################################

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


    def __init__(self, app = None, app_name = None, hosts = [], conf = None, key = None, verbose_level = 10, dev = False):

        # Set init verbosity
        if not verbose_level == None:
            self.INIT_VERBOSE = verbose_level


        # Development mode
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

        self.print_screen('[+] Loading default configuration', init=True, new_line_up = False)
        self.load_config(DEFAULT_CONFIG)

        # Load default configuration
        if conf == None and key == None:
            self.print_screen('[!] No configuration provided. Running default configuration', init=True, new_line_up = False)
        
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
        if not app is None:
            self.register_security_checks(app)

        # Load XSS ML model
        xss_model_loaded = False
        if not dev:
            xss_model_file = 'xss_model-'+XSS_MODEL_VERSION
        else:
            xss_model_file = 'ml-engines/xss_model-dev'

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

        # Load SQLI ML model
        sqli_model_loaded = False
        if not dev:
            sqli_model_file = 'sqli_model-'+SQLI_MODEL_VERSION
        else:
            sqli_model_file = 'ml-engines/sqli_model-dev'

        ## From source
        try:
            self.sqli_model = pickle.load(open(sqli_model_file,'rb'))
        except:
            pass
        else:
            sqli_model_loaded = True

        ## From package
        if not sqli_model_loaded:
            try:
                sqli_model_file = pkg_resources.resource_filename('pyrasp', 'data/'+sqli_model_file)
                self.sqli_model = pickle.load(open(sqli_model_file,'rb'))
            except:
                pass
            else:
                sqli_model_loaded = True

        if not sqli_model_loaded:
            self.print_screen('[!] SQLI model not loaded', init=False, new_line_up = False)
        else:
            self.print_screen('[+] SQLI model loaded', init=True, new_line_up = False)


        # Start logging
        if self.LOG_ENABLED:
            self.start_logging()

        # Start beacon
        if self.KEY:
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
    
    def register_security_checks(self, app):
        pass

    ####################################################
    # BEACON & UPDATES
    ####################################################

    def start_beacon(self, key):

        self.print_screen('[+] Starting beacon process', init=True, new_line_up = False)
        self.BEACON_THREAD = Thread(target=beacon_thread, args=(self, key))
        self.BEACON_THREAD.start()
        
    def send_beacon(self, key):

        beacon_url = f'{PCB_PROTOCOL}://{PCB_SERVER}/rasp/beacon'
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent
        data = { 
            'key': key, 
            'version': VERSION, 
            'cpu': cpu, 
            'mem': mem,
            'requests': self.REQUESTS }

        error = False

        # Send requets to server
        try:
            r = requests.post(beacon_url, json=data)
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
    
        # Reset requests count
        if not error:
            self.REQUESTS = {
                'success': 0,
                'errors': 0,
                'attacks': 0
            }


        # Set configuration
        if not error and server_data.get('config'):
            self.print_screen('[PyRASP] Loading new configuration')
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
            self.print_screen('[PyRASP] Error connecting to cloud server')
            #self.print_screen(f'[!] Error connecting to cloud server: {str(e)}', init = True)
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

    ####################################################
    # LOGGING
    ####################################################

    def start_logging(self):

        self.print_screen('[+] Starting logging process', init=True, new_line_up = False)
        self.LOG_QUEUE = Queue()
        self.LOG_THREAD = Thread(target=log_thread, args=(self.LOG_QUEUE, self.LOG_SERVER, self.LOG_PORT, self.LOG_FORMAT, self.LOG_PROTOCOL ))
        self.LOG_THREAD.start()
        
    def log_security_event(self, event_type, source_ip, user = None, details = {}):

        try:
            security_log = make_security_log(self.APP_NAME, event_type, source_ip, self.LOG_FORMAT, user, details)
        except:
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
        data = { 'key': key, 'version': VERSION, 'platform': self.PLATFORM }

        error = False
        
        # Send requets to server
        try:
            r = requests.post(config_url, json=data)
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
            self.log_security_event(ATTACKS[attack_id], source_ip, None, attack_details)

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
                if attack_id == None:
                    if self.SECURITY_CHECKS.get('flood'):
                        attack = self.flood_and_brute_check(request_path, source_ip, timestamp)
                            
                # Check HTTP Parameter Pollution
                if attack == None:
                    if self.SECURITY_CHECKS.get('hpp'):
                        attack = self.check_hpp(request)

                # Get injectable params
                if attack == None and inject_vectors == None:
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

        return attack

    # Outbound attacks
    def check_outbound_attacks(self, response_content, request_path, source_ip, timestamp, error):

        attack = None

        # Check flood errors
        if error:

            if self.SECURITY_CHECKS.get('flood'):
                attack = self.flood_and_brute_check(request_path, source_ip, timestamp, error=True)

        # Check DLP
        if not error and attack == None:

            if self.SECURITY_CHECKS.get('dlp') and not response_content == None:
                attack = self.check_dlp(response_content)

        return attack
    
    # Alter response
    def process_response(self, response, attack = None):

        if not attack == None:
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


                # Test signatures
                '''
                for signature in SQL_INJECTIONS_SIGNATURES:
                    if re.search(signature, injection, re.IGNORECASE):
                        sql_injection = True
                        break
                '''

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

                    if injection.count('[') > 8 and injection.count(']') > 8:
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
                vectors['user_agent'] = headers[header]

            # Refererer
            elif header.lower() == 'referer':
                vectors['referer'] = headers[header]
            
            # Other headers
            else:
                vectors['headers_names'].append(header)
                vectors['headers_values'].append(headers[header])

        return vectors
    
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
            
class FlaskRASP(PyRASP):

    def __init__(self, app, app_name=None, hosts=[], conf=None, key=None, verbose_level=10, dev=False):
        self.PLATFORM = 'Flask'
        super().__init__(app, app_name, hosts, conf, key, verbose_level, dev)

        if self.LOG_ENABLED or self.KEY:
            signal.signal(signal.SIGINT, partial(handle_kb_interrupt, self.LOG_QUEUE))
        
    def register_security_checks(self, app):
        self.set_before_security_checks(app)
        self.set_after_security_checks(app)

    ####################################################
    # SECURITY CHECKS
    ####################################################

    # Incoming request
    def set_before_security_checks(self, app):

        @app.before_request
        def before_request_callback():

            (host, request_method, request_path, source_ip, timestamp) = self.get_params(request)
            
            attack = self.check_inbound_attacks(host, request_method, request_path, source_ip, timestamp, request)

            # Send attack status in status code for handling by @after_request
            if not attack == None:
                self.handle_attack(attack, host, request_path, source_ip, timestamp)
                return self.GTFO_MSG, 1
           
    # Outgoing responses
    def set_after_security_checks(self, app):
        @app.after_request
        def after_request_callback(response):

            (host, request_method, request_path, source_ip, timestamp) = self.get_params(request)

            error = False
            response_attack = None
            request_attack = False

            # Get attack from @before_request checks
            if response.status_code == 1:
                request_attack = True

            # Check if response is error
            if request_attack or response.status_code >= 400:
                error = True

            # Check brute force and flood
            try:
                response_content =  response.get_data(True)
            except:
                pass
            else:
                response_attack = self.check_outbound_attacks(response_content, request_path, source_ip, timestamp, error)
                        
            if response_attack and not request_attack == None:
                self.handle_attack(response_attack, host, request_path, source_ip, timestamp)

            response = self.process_response(response, request_attack or response_attack)

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

    def __init__(self, app, app_name=None, hosts=[], conf=None, key=None, verbose_level=10, dev=False):
        self.PLATFORM = 'FastAPI'

        # Init
        super().__init__(app, app_name, hosts, conf, key, verbose_level, dev)

        if self.LOG_ENABLED:
            @app.on_event("shutdown")
            async def shutdown_event():
                global STOP_THREAD
                self.LOG_QUEUE.put('--STOP--')
                STOP_THREAD = True

    def register_security_checks(self, app):

        @app.middleware('http')
        async def security_checks_setup(request: Request, call_next):
    
            inbound_attack = None
            outbound_attack = None
            error = False

            # Get Main params
            (host, request_method, request_path, source_ip, timestamp) = self.get_params(request)

            # Get vectors - need to do it here as async
            vectors = await self.get_vectors(request) 

            # Check inboud attacks
            inbound_attack = self.check_inbound_attacks(host, request_method, request_path, source_ip, timestamp, request, vectors)
              
            # Send response
            if not inbound_attack:
                response = await call_next(request)
            else:
                response = FastApiResponse()
            
            # Check outbound attacks
            if inbound_attack or response.status_code >= 400:
                error = True
                response_content = None
            else:
                
                response_body = [chunk async for chunk in response.body_iterator]
                response.body_iterator = iterate_in_threadpool(iter(response_body))
                response_content = response_body[0].decode()
                
            outbound_attack = self.check_outbound_attacks(response_content, request_path, source_ip, timestamp, error)

            if outbound_attack:
                self.handle_attack(outbound_attack, host, request_path, source_ip, timestamp)
            elif inbound_attack:
                self.handle_attack(inbound_attack, host, request_path, source_ip, timestamp)

            
            response = self.process_response(response, inbound_attack or outbound_attack)

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
                vectors['user_agent'] = headers[header]

            # Refererer
            elif header.lower() == 'referer':
                vectors['referer'] = headers[header]
            
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

        # Init
        super().__init__(None, None, [], conf, key, 10, False)

    def __call__(self, request):

        inbound_attack = None
        outbound_attack = None
        error = False

        # Get Main params
        (host, request_method, request_path, source_ip, timestamp) = self.get_params(request)

        # Check inboud attacks
        inbound_attack = self.check_inbound_attacks(host, request_method, request_path, source_ip, timestamp, request)

        if not inbound_attack:
            response = self.get_response(request)
        else:
            response = HttpResponse()

        if inbound_attack or response.status_code >= 400:
            error = True
            response_content = None
        else:
            response_content = response.content.decode()

        outbound_attack = self.check_outbound_attacks(response_content, request_path, source_ip, timestamp, error)

        if outbound_attack:
            self.handle_attack(outbound_attack, host, request_path, source_ip, timestamp)
        elif inbound_attack:
            self.handle_attack(inbound_attack, host, request_path, source_ip, timestamp)

        response = self.process_response(response, inbound_attack or outbound_attack)

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
    