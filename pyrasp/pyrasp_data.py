#
# VERSION
#

DATA_VERSION = '1.1.0'
XSS_MODEL_VERSION = '3.0.0'
SQLI_MODEL_VERSION = '3.0.0'

#
# PLATFORMS
#

CLOUD_FUNCTIONS = ['AWS Lambda', 'Google Cloud Function', 'Azure Function' ]

# 
# UTILS
#

PATTERN_CHECK_FUNCTIONS = [ 'regex', 'starts', 'contains', 'match' ]

#
# DETECTION
#

ATTACKS = [
    'Blacklisted IP',       # 0
    'Invalid Path',         # 1
    'Flood',                # 2
    'Host Spoofing',        # 3
    'Decoyed',              # 4
    'Format Mismatch',      # 5
    'SQL Injection',        # 6
    'XSS',                  # 7
    'Parameter Pollution',  # 8
    'Command Injection',    # 9
    'Forbidden Header',     # 10
    'Data Leak Prevention', # 11
    'Brute Force',          # 12
    'Zero-Trust'            # 13
]

BRUTE_FORCE_ATTACKS = [ 1, 3, 5, 10 ]

# Attacks IDs
ATTACK_BLACKLIST = 0
ATTACK_PATH = 1
ATTACK_FLOOD = 2
ATTACK_SPOOF = 3
ATTACK_DECOY = 4
ATTACK_FORMAT = 5
ATTACK_SQLI = 6
ATTACK_XSS = 7
ATTACK_HPP = 8
ATTACK_CMD = 9
ATTACK_HEADER = 10
ATTACK_DLP = 11
ATTACK_BRUTE = 12
ATTACK_ZTAA = 13

ATTACKS_CHECKS = [
    'blacklist',
    'path',
    'flood',
    'spoofing',
    'decoy',
    'format',
    'sqli',
    'xss',
    'hpp',
    'command',
    'headers',
    'dlp',
    'brute',
    'ztaa'
]

ATTACKS_CODES = {
    ATTACK_BLACKLIST: ['PCB000'],
    ATTACK_PATH: ['T1592.002', 'PCB001'],
    ATTACK_FLOOD: ['T1498', 'PCB002'],
    ATTACK_SPOOF: ['T1594', 'PCB003'],
    ATTACK_DECOY: ['T1592.002', 'PCB004'],
    ATTACK_FORMAT: ['PCB005'],
    ATTACK_SQLI: ['T1111', 'PCB006'],
    ATTACK_XSS: ['T1059.007', 'PCB007'],
    ATTACK_HPP: ['T1211', 'PCB008' ],
    ATTACK_CMD: ['T1059', 'PCB009'],
    ATTACK_HEADER: ['PCB010'],
    ATTACK_DLP: ['T1052', 'PCB011'],
    ATTACK_BRUTE : ['T1110', 'PCB012'],
    ATTACK_ZTAA: [ 'PCB013' ]
}
   

SQL_INJECTIONS_VECTORS = [ 'path', 'cookies', 'qs_values', 'post_values', 'json_values', 'user_agent', 'referer' ]

XSS_VECTORS = [ 'path', 'cookies', 'qs_values', 'post_values', 'json_values', 'headers_values', 'referer' ]
COMMAND_INJECTIONS_VECTORS = [ 'qs_values', 'post_values', 'json_values' ]

DLP_PATTERNS = {
    'phone': [ r'(011|00|\+)((?:9[679]|8[035789]|6[789]|5[90]|42|3[578]|2[1-689])|9[0-58]|8[1246]|6[0-6]|5[1-8]|4[013-9]|3[0-469]|2[70]|7|1)(?:\W*\d){0,13}\d' ],
    'cc': [ r'(?:4[0-9]{12}(?:[0-9]{3})?|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}|3[47][0-9]{13})' ],
    'key': [ r'-----BEGIN ([A-Z]+ )?PRIVATE KEY( BLOCK)?-----' ],
    'hash': [ r'([a-f0-9]{8}){4,5,7,8,12,16}' ], # MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
    'windows': [
        r'(\$NT\$)?[a-f0-9]{32}$', # NTLM
        r'([^\\\/:*?\"<>|]{1,20}:)?[a-f0-9]{32}(:[^\\\/:*?\"<>|]{1,20})?', # Domain Cached
        r'([^\\\/:*?\"<>|]{1,20}:)?(\\$DCC2\\$10240#[^\\\/:*?\"<>|]{1,20}#)?[a-f0-9]{32}', # Domain Cached 2
        r'[^\\\/:*?\"<>|]{1,20}[:]{2,3}([^\\\/:*?\"<>|]{1,20})?:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}', # NTLMv1
        r'([^\\\/:*?\"<>|]{1,20}\\)?[^\\\/:*?\"<>|]{1,20}[:]{2,3}([^\\\/:*?\"<>|]{1,20}:)?[^\\\/:*?\"<>|]{1,20}:[a-f0-9]{32}:[a-f0-9]+', # NTLMv2
        r'[a-f-0-9]{32}:[a-f-0-9]{32}', # SAM
    ],
    'linux': [
        r'\$(1|2(a|y)?|5|6)\$[a-z0-9\/.]{0,96}\$[a-z0-9\/.]{22,128}?' , # MD5 / Blowfish / SHA-256 / SHA-512
        r'\$(y|7)\$[.\/A-Za-z0-9]+\$[.\/A-Za-z0-9]{,86}\$[.\/A-Za-z0-9]{43}', # Yescrypt
    ]

}

B64_PATTERN = r'^(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'

#
# DEFAULT CONFIGURATION
#

DEFAULT_SECURITY_CHECKS = {
    "path": 1,
    "headers": 0,
    "flood": 2,
    "spoofing": 0,
    "decoy": 2,
    "format": 2,
    "sqli": 2,
    "xss": 2,
    "hpp": 2,
    "command": 2,
    "method": 0,
    "dlp": 0,
    "brute": 2,
    "ztaa": 0
}

DEFAULT_CONFIG = {
    "HOSTS" : [],
    "APP_NAME" : "Web Server",
    "GTFO_MSG" : 'Blocked',
    "DENY_STATUS_CODE": 403,

    "VERBOSE" : 0,
    "DECODE_B64" : True,

    "SECURITY_CHECKS" : DEFAULT_SECURITY_CHECKS,    

    "WHITELIST": [],
    "IGNORE_PATHS" : [ r"^/favicon.ico$",r"^/robots.txt$",r"^/sitemap\.(txt|xml)$"],

    "FORBIDDEN_HEADERS": [ ],

    "BRUTE_AND_FLOOD_PATHS" : [r"^/"],
    "FLOOD_DELAY" : 60,
    "FLOOD_RATIO" : 50,
    "ERROR_FLOOD_DELAY" : 10,
    "ERROR_FLOOD_RATIO" : 100,

    "BLACKLIST_DELAY" : 3600,
    "BLACKLIST_OVERRIDE" : False,
    "BLACKLIST_SHARE" : False,

    "DECOY_ROUTES" : [ 
        [ "/admin", "ends" ],
        [ "/login", "ends" ],
        [ "/logs", "ends" ],
        [ "/version", "ends" ],   
        [ "/cgi-bin/", "starts" ],                      
        [ "/remote/", "starts" ],                     
        [ "/.env", "starts" ],                     
        [ "/owa/", "starts" ],                        
        [ "/autodiscover", "starts" ],
        [ "/Autodiscover", "starts" ],
        [ "/.git/", "starts" ],                
        [ "/.aws/ ", "starts" ],
    ],

    "EXCEPTIONS" : [],

    "XSS_PROBA" : 0.6,
    "SQLI_PROBA" : 0.6,

    "DLP_PHONE_NUMBERS": False,
    "DLP_CC_NUMBERS": False,
    "DLP_PRIVATE_KEYS": False,
    "DLP_HASHES": False,
    "DLP_WINDOWS_CREDS": False,
    "DLP_LINUX_CREDS": False,
    "DLP_LOG_LEAKED_DATA": False,

    "LOG_ENABLED": False,
    "LOG_FORMAT": "Syslog",
    "LOG_SERVER" : "127.0.0.1",    
    "LOG_PORT": 514,
    "LOG_PROTOCOL": "UDP",
    "LOG_PATH": "",
    "RESOLVE_COUNTRY": True,

    "CHANGE_SERVER": True,
    "SERVER_HEADER": "Apache",

    "BEACON": False,
    "TELEMETRY_DATA": False,
    "BEACON_URL": None,
    "BEACON_DELAY": 30,

    "ZTAA_KEY_HEADER": "pcb-ztaa",
    "ZTAA_KEY": "",
    "ZTAA_BROWSER_VERSION": False
}

