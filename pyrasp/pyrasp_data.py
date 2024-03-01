#
# VERSION
#

DATA_VERSION = '1.1.0'
XSS_MODEL_VERSION = '1.1.0'
SQLI_MODEL_VERSION = '1.0.0'

# 
# CLOUD SERVER
#

PCB_SERVER = 'rasp.paracyberbellum.io:8080'
PCB_PROTOCOL = 'http'

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
    'Data Leak Prevention'  # 11
]

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
    'dlp'
]

SQL_INJECTIONS_SIGNATURES = [ '@@VERSION', '@@DATABASE', 'master\.\.xp_cmdshell', 'updatexml\(']
SQL_INJECTIONS_FP = ['^[a-zA-Z][\\w]+\\s*&\\s*[a-zA-Z][\\w]+$']

SQL_INJECTIONS_POINTS = [
    'select * from test where id={{vector}}',
    'select * from test limit {{vector}}' 
    'select * from test limit 1 offset {{vector}}', 
    'select * from test order by {{vector}}',
    'select * from test group by {{vector}}',
    'update test set var={{vector}}',
    'update test set var=value where column_name={{vector}}',
    'insert into test values(null,{{vector}})',
]

SQL_INJECTIONS_VECTORS = [ 'path', 'cookies', 'qs_values', 'post_values', 'json_values' ]
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

#
# DEFAULT CONFIGURATION
#

DEFAULT_CONFIG = {
    "HOSTS" : [],
    "APP_NAME" : "Web Server",
    "GTFO_MSG" : 'Blocked',
    "DENY_STATUS_CODE": 403,

    "VERBOSE" : 0,
    "DECODE_B64" : True,

    "SECURITY_CHECKS" : {
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
        "dlp": 0
    },    

    "WHITELIST": [],
    "IGNORE_PATHS" : ["^/favicon.ico$","^/robots.txt$","^/sitemap\.(txt|xml)$"],

    "FORBIDDEN_HEADERS": [ ],

    "BRUTE_AND_FLOOD_PATHS" : ["^/"],
    "FLOOD_DELAY" : 60,
    "FLOOD_RATIO" : 50,
    "ERROR_FLOOD_DELAY" : 10,
    "ERROR_FLOOD_RATIO" : 100,

    "BLACKLIST_DELAY" : 3600,
    "BLACKLIST_OVERRIDE" : False,

    "DECOY_ROUTES" : [ 
        "/admin", "/login", "/logs", "/version",    
        "/cgi-bin/",                                
        "/remote/",                                 
        "/.env",                                    
        "/owa/",                                    
        "/autodiscover", "/Autodiscover",           
        "/.git/",                                   
        "/.aws/ "                                 
    ],

    "XSS_PROBA" : 0.60,
    "MIN_XSS_LEN": 16,

    "SQLI_PROBA" : 0.725,
    "MIN_SQLI_LEN": 8,

    "DLP_PHONE_NUMBERS": False,
    "DLP_CC_NUMBERS": False,
    "DLP_PRIVATE_KEYS": False,
    "DLP_HASHES": False,
    "DLP_WINDOWS_CREDS": False,
    "DLP_LINUX_CREDS": False,

    "LOG_ENABLED": False,
    "LOG_FORMAT": "Syslog",
    "LOG_SERVER" : "127.0.0.1",    
    "LOG_PORT": 514,
    "LOG_PROTOCOL": "UDP",

    "CHANGE_SERVER": True,
    "SERVER_HEADER": "Apache",

    "BEACON_DELAY": 5
}

