# Python RASP
## Overview
`pyrasp` is a Runtime Application Self Protection package for Python-based Web Servers. It protects against the main attacks web applications are exposed to from within the application. 

One specificity of `pyrasp` relies on the fact that it does not use signatures (except very few specific cases of SQL Injection). Instead it will leverage decoys, thresholds, system and application internals, machine learning and grammatical analysis.

> Version 0.1.x only supports Flask

Security modules, technology, and operations are provided in the table below.
| Module | Technology | Function |
| - | - | - |
| Flood & Brute Force | Threshold | Identifies and blocks repetitive connections or attempts from same source |
| Forbidden Headers | List Validation | Denies requests with specified headers | 
| Requests Validation | Application Internals | Denies requests with invalid path or methods | 
| Spoofing | Header Validation | Denies requests with mismatching Host header |
| Decoy | Path | Identifies request to known scanned paths |
| SQL Injection | Grammatical Analysis + Signatures | Detects and blocks SQL injection attempts |
| XSS | Machine Learning | Detects and XSS attempts |
| Command Injection | System Internals | Prevents command injections attempts |


## Install
### From PyPi (Recommended)
```
pip install pyrasp
```
### From Source
```
git clone https://github.com/rbidou/pyrasp
cd pyrasp
pip install -r requirements.txt
```
## Run
### Flask
`pyrasp` requires 2 lines of code to run.

`from pyrasp import <rasp_class>`

`<rasp_class>(<framework_instrance>, conf = <configuration_file>)`

> **IMPORTANT** the second line must be located the main section of the code

Below an example for Flask
```pyhton
from pyrasp import FlaskRASP
app = Flask(__name__)
if __name__ == 'main':
    FlaskRASP(app, conf = 'rasp/config.json')
    app.run()
```

## Configuration
Configuration is set from a JSON file.
### Example File
```json
{
    "HOSTS" : ["mysite.mydomain.com"],
    "APP_NAME" : "Web Server",
    "GTFO_MSG" : "<html><head /><body><h1>You have been blocked</h1></body></html>",

    "VERBOSE" : 10,
    "DECODE_B64" : true,

    "SECURITY_CHECKS" : {
        "path": 2,
        "headers": 2,
        "flood": 2,
        "spoofing": 2,
        "decoy": 2,
        "format": 2,
        "sqli": 2,
        "xss": 2,
        "hpp": 2,
        "command": 2
    },    

    "WHITELIST": [],

    "IGNORE_PATHS" : ["^/css","^/js","^/img"],

    "BRUTE_AND_FLOOD_PATHS" : ["^/"],
    "FLOOD_DELAY" : 60,
    "FLOOD_RATIO" : 50,
    "ERROR_FLOOD_DELAY" : 10,
    "ERROR_FLOOD_RATIO" : 100,

    "BLACKLIST_DELAY" : 3600,
    "BLACKLIST_OVERRIDE" : false,

    "DECOY_ROUTES" : [ 
        "/admin", "/login", "/logs", "/version",    
        "/cgi-bin/",                                
        "/remote/",                                 
        "/.env",                                    
        "/owa/",                                    
        "/autodiscover", "/Autodiscover",           
        "/.git/",                                   
        "/.aws/ ",
        "/.well-known/"                                 
    ],

    "XSS_PROBA" : 0.80,
    "MIN_XSS_LEN": 16,

    "LOG_ENABLED": false,
    "LOG_FORMAT": "Syslog",
    "LOG_SERVER": "127.0.0.1",        
    "LOG_PORT": 514,    
    "LOG_PROTOCOL": "UDP"
}
```
### Parameters
| Parameter | Type | Values | Usage |
| - | - | - | - |
| `HOSTS` | list of trings | any | List of valid 'Host' headers checked for spoofing detection |
| `APP_NAME` | string | any | Identification of the web application in the logs |
| `GTFO_MSG` | string | any | Message displayed when request is blocked. HTML page code is authorized |
| `VERBOSE` | integer | any | Verbosity level - *see "Specific Parameters Values" section below* |
| `DECODE_B64` | boolean | true, false | Decode Base64-encoded payloads |
| `SECURITY_CHECKS` | integer |  0, 1, 2, 3 | Security modules status - *see "Specific Parameters Values" section below*  |
| `WHITELIST` | list of strings | any | Whitelisted source IP addresses |
| `IGNORE_PATHS` | list of regexp | any | Paths to which requests will entirely bypass security checks including blacklist |
| `BRUTE_AND_FLOOD_PATH` | list of regexp | any | Paths for which flood and brute force threshold will be enabled |
| `FLOOD_DELAY` | integer | any | Sliding time window (in second) against which request threshold is calculated |
| `FLOOD_RATIO` | integer | any | Requests threshold |
| `ERROR_FLOOD_DELAY` | integer | any | Sliding time window (in second) against which error threshold is calculated |
| `ERROR_FLOOD_RATIO` | integer | any | Errors threshold |
| `BLACKLIST_DELAY` | integer | any | Duration (in seconds) of source IP blacklisting |
| `BLACKLIST_OVERRIDE` | boolean | true, false | Ignore source IP blacklisting (usually for testing) |
| `DECOY_ROUTES` | list of strings | any | Paths generating immediate detection |
| `XSS_PROBA` | float | 0 to 1 | Machine Learning prediction minimum probability (should be left to 0.80) |
| `MIN_XSS_LEN` | integer | any | Minimum payload size to be checked by XSS engine |
| `LOG_ENABLED` | boolean | true, false | Enable event logging |
| `LOG_FORMAT` | string | syslog, json | Format of event log - *see "Event Logs Format" section below* |
| `LOG_SERVER` | string | any | Log server IP address or FQDN |
| `LOG_PORT` | integer | 1 - 36635 | Log server port |
| `LOG_PROTOCOL` | string | tcp, udp, http, https | Log server protocol (tcp or udp for syslog, http or https for json) |

### Specific Parameters Values
**`SECURITY_CHECKS`**
| Value | Usage |
| - | - |
| 0 | Disabled |
| 1 | Enabled, no Blacklisting |
| 2 | Enabled, Blacklisting activated |

> Notes
> - `spoofing` module refers to "Host" header validation
> - `format` is unused for now

**`VERBOSE`**
| Value | Messages displayed |
| - | - |
| 0 | Start, Stop, Configuration load status |
| 10+ | Configuration loading details, XSS model load status, Logging process status, Attacks detection |
| 100+ | Configuration details |

### Default Configuration
```json
{
    "HOSTS" : [""],
    "APP_NAME" : "Web Server",
    "GTFO_MSG" : "Blocked",

    "VERBOSE" : 10,
    "DECODE_B64" : true,

    "SECURITY_CHECKS" : {
        "blacklist": 2,
        "path": 2,
        "headers": 1,
        "flood": 2,
        "spoofing": 0,
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
    "BLACKLIST_OVERRIDE" : false,

    "DECOY_ROUTES" : [ 
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

    "LOG_ENABLED": false,
    "LOG_FORMAT": "Syslog",
    "LOG_SERVER" : "127.0.0.1",    
    "LOG_PORT": 514,
    "LOG_PROTOCOL": "UDP"
}
```

## Event Logs Format
### Parameters
| Parameter | Format | Detail |
| - | - | - |
| `<event_time>` | %Y/%m/%d %H:%M:%S | Time on the system running `pyrasp` |
| `<application_name>` | string | Value of the `APP_NAME` parameter |
| `<event_type>` | string | Type of attack - *see "Attack Types" section below* |
| `<source_ip>` | string | IP address of the attack source |
| `<country>` | string | Country of the source address ("Private" if internal network) |
| `<location>` | string | Location of the offending payload - *see "Payload Locations" section below* |
| `<payload>` | string | Suspicious payload (base64 decoded) |

### JSON Logs
```json
{
    "time": "<event_time>",
    "application": "<application_name>",
    "log_data": [
        "<event_type>", 
        "<source_ip>", 
        "<country>",
        {
            "location": "<location>",
            "payload": "<payload>"
        }
    ]
}
```

### Syslog Logs
```
[<event_time>] "<application_name>" - "<event_type>" - "<source_ip>" - "<country>" - "<location>:<payload>"
```

### Attack Types
Possible values for attack types are:
- Blacklisted IP
- Invalid Path
- Flood
- Host Spoofing
- Decoyed
- Format Mismatch
- SQL Injection
- XSS
- Parameter Pollution
- Command Injection
- Forbidden Header

### Payload Locations
| Value | Location |
| - | - |
| `source_ip` | Source IP |
| `request` | Request path or method |
| `path` | Request path |
| `host` | "Host" header |
| `headers_names` | Request header name |
| `headers_values` | Request header value |
| `cookies` | Cookies |
| `user_agent` | "User-Agent" header |
| `referer` | "Referer" header |
| `qs_variables` | Query String variable name |
| `qs_values` | Qyery Strubg value |
| `post_variables` | Posted data variable name |
| `post_values` | Posted data value |
| `json_keys` | JSON key name |
| `json_values` | JSON key value |

## Contacts
Renaud Bidou - renaud@paracyberbellum.io










