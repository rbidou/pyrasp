#
# VERSION
#

DATA_VERSION = '1.0.0'
XSS_MODEL_VERSION = '1.0.0'

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
    'Forbidden Header'      # 10
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

ATTACKS_CHECKS = [
    "blacklist",
    "path",
    "flood",
    "spoofing",
    "decoy",
    "format",
    "sqli",
    "xss",
    "hpp",
    "command",
    "headers"
]

SQL_INJECTIONS_SIGNATURES = [ '@@VERSION', '@@DATABASE', 'master\.\.xp_cmdshell', 'updatexml\(']

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

#
# DEFAULT CONFIGURATION
#

DEFAULT_CONFIG = {
    "HOSTS" : ["127.0.0.1:8080"],
    "APP_NAME" : "Web Server",
    "GTFO_MSG" : '<html><body><div style="display: flex; width:50%; min-width:350px; padding-top:10vh; margin: auto; font-size: x-large">I know you are trying to do something. <br>You just can\'t imagine how painful it is, for me as well as for you. <br>I think you should just stop trying to do something</div></body></html>',

    "VERBOSE" : 0,
    "DECODE_B64" : True,

    "SECURITY_CHECKS" : {
        "blacklist": 2,
        "path": 2,
        "headers": 1,
        "flood": 2,
        "spoofing": 2,
        "decoy": 2,
        "format": 2,
        "sqli": 2,
        "xss": 2,
        "hpp": 2,
        "command": 2,
        "method": 2
    },    

    "WHITELIST": [],

    "IGNORE_PATHS" : ["^/css","^/js","^/img","^/favicon.ico$","^/robots.txt$","^/sitemap\.(txt|xml)$"],

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

    "XSS_PROBA" : 0.80,
    "MIN_XSS_LEN": 16,

    "LOG_ENABLED": True,
    "LOG_FORMAT": "Syslog",
    "LOG_SERVER" : "127.0.0.1",    
    "LOG_PORT": 514,
    "LOG_PROTOCOL": "UDP"
}

