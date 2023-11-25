# Python RASP
## Overview
`pyrasp` is a Runtime Application Self Protection package for Python-based Web Servers. It protects against the main attacks web applications are exposed to from within the application. 

One specificity of `pyrasp` relies on the fact that it does not use signatures. Instead it will leverage decoys, thresholds, system and application internals, machine learning and grammatical analysis.

Security modules, technology, and operations are provided in the table below.
| Module | Technology | Function |
| - | - | - |
| Flood & Brute Force | Threshold | Identifies and blocks repetitive connections or attempts from same source |
| Forbidden Headers | List Validation | Denies requests with specified headers | 
| Requests Validation | Application Internals | Denies requests with invalid path or methods | 
| Spoofing | Header Validation | Denies requests with mismatching Host header |
| Decoy | Path | Identifies request to known scanned paths |
| SQL Injection | Grammatical Analysis + Machine Learning | Detects and blocks SQL injection attempts |
| XSS | Machine Learning | Detects and XSS attempts |
| Command Injection | System Internals | Prevents command injections attempts |
| HTTP Parameter Polution | Grouping | Prevents HPP attacks attempts |

## Supported Frameworks
`pyrasp` 0.3.x supports Flask, FastAPI and Flask

> **IMPORTANT** FastAPI support requires `starlette` >= 0.28.0

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

### Classes

| Framework | `rasp_class` | Note |
| - | - | - |
| Flask | FaskRASP | |
| FastAPI | FastApiRASP | **IMPORTANT** Requires starlette >= 0.28.0 |
| Django | DjangoRASP | |

### Flask & FastAPI

**Guidelines**

`pyrasp` requires 2 lines of code to run.

`from pyrasp.pyrasp import <rasp_class>`

`<rasp_class>(<framework_instrance>, conf = <configuration_file>)`

**Examples**

```python
from pyrasp import FlaskRASP

app = Flask(__name__)
FlaskRASP(app, conf = 'rasp.json')
```

```python
from pyrasp import FastApiRASP
app = FastAPI()
rasp = FastApiRASP(app, conf='rasp.json')
```

### Django

**Guidelines**

The `pyrasp` class must be added to the `MIDDLEWARE` variable in the `settings.py` file of the Django application.
Additionally a `PYRASP_CONF` variable must be added to the same file. It contains the path of the configuration file.

**Example**

```python
PYRASP_CONF = 'rasp.json'

MIDDLEWARE = [
    'pyrasp.pyrasp.DjangoRASP',
    ...
]
```

## Startup
At startup of the application `pyrasp` loading information is displayed.

```
### PyRASP v0.3.1 ##########
[+] Starting PyRASP
[+] Loading configuration from rasp.json
[+] XSS model loaded
[+] SQLI model loaded
[+] PyRASP succesfully started
############################
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

    "SQLI_PROBA" : 0.725,
    "MIN_SQLI_LEN": 8,

    "LOG_ENABLED": false,
    "LOG_FORMAT": "Syslog",
    "LOG_SERVER": "127.0.0.1",        
    "LOG_PORT": 514,    
    "LOG_PROTOCOL": "UDP"
}
```
### Parameters
**Generic Parameters Table**
| Parameter | Type | Values | Default | Usage |
| - | - | - | - | - |
| `HOSTS` | list of trings | any | `[]` | List of valid 'Host' headers checked for spoofing detection |
| `APP_NAME` | string | any | `["Web Server"]` | Identification of the web application in the logs |
| `GTFO_MSG` | string | any | `["Blocked"]` | Message displayed when request is blocked. HTML page code is authorized |
| `VERBOSE` | integer | any | `0` | Verbosity level - *see "Specific Parameters Values" section below* |
| `DECODE_B64` | boolean | true, false | `true` | Decode Base64-encoded payloads |
| `SECURITY_CHECKS` | integer |  0, 1, 2, 3 | see below | Security modules status - *see "Specific Parameters Values" section below*  |
| `WHITELIST` | list of strings | any | `[]` | Whitelisted source IP addresses |
| `IGNORE_PATHS` | list of regexp | any | see below |Paths to which requests will entirely bypass security checks including blacklist |
| `BRUTE_AND_FLOOD_PATH` | list of regexp | any | `["^/"]` | Paths for which flood and brute force threshold will be enabled |
| `FLOOD_DELAY` | integer | any | `60` | Sliding time window (in second) against which request threshold is calculated |
| `FLOOD_RATIO` | integer | any | `50` | Requests threshold |
| `ERROR_FLOOD_DELAY` | integer | any | `10` | Sliding time window (in second) against which error threshold is calculated |
| `ERROR_FLOOD_RATIO` | integer | any | `100` | Errors threshold |
| `BLACKLIST_DELAY` | integer | any | `3600` | Duration (in seconds) of source IP blacklisting |
| `BLACKLIST_OVERRIDE` | boolean | true, false | `false` | Ignore source IP blacklisting (usually for testing) |
| `DECOY_ROUTES` | list of strings | any | see below | Paths generating immediate detection |
| `XSS_PROBA` | float | 0 to 1 | `0.60` | Machine Learning prediction minimum probability for XSS (should be left to 0.8) |
| `MIN_XSS_LEN` | integer | any | `16` | Minimum payload size to be checked by XSS engine |
| `SQLI_PROBA` | float | 0 to 1 | `0.725` | Machine Learning prediction minimum probability for SQL injections (should be left to 0.725) |
| `MIN_SQLI_LEN` | integer | any | `16` | Minimum payload size to be checked by SQLI engine |
| `LOG_ENABLED` | boolean | true, false | `false` | Enable event logging |
| `LOG_FORMAT` | string | syslog, json | `"syslog"` | Format of event log - *see "Event Logs Format" section below* |
| `LOG_SERVER` | string | any | `"127.0.0.1"` | Log server IP address or FQDN |
| `LOG_PORT` | integer | 1 - 36635 | `514` | Log server port |
| `LOG_PROTOCOL` | string | tcp, udp, http, https | `"udp"` | Log server protocol (tcp or udp for syslog, http or https for json) |

**Default ignore paths**
```json
"IGNORE_PATHS" : ["^/favicon.ico$","^/robots.txt$","^/sitemap\.(txt|xml)$"]
```

**Default decoy paths**
```json
"DECOY_ROUTES" : [ 
        "/admin", "/login", "/logs", "/version",    
        "/cgi-bin/",                                
        "/remote/",                                 
        "/.env",                                    
        "/owa/",                                    
        "/autodiscover", "/Autodiscover",           
        "/.git/",                                   
        "/.aws/ "                                 
    ]
```

### Specific Parameters Values
**`SECURITY_CHECKS`**
| Value | Usage |
| - | - |
| 0 | Disabled |
| 1 | Enabled, no Blacklisting |
| 2 | Enabled, Blacklisting activated |

**Default security checks values**
| Parameter | Function | Default Value |
| - | - | - |
| `flood` | Flood & Brute Force | 2 |
| `headers`| Forbidden Headers | 0 | 
| `path` | Requests Validation | 1 | 
| `spoofing`| Spoofing | 0 |
| `decoy`| Decoy | Path | 2 |
| `sqli`| SQL Injection | 2 |
| `xss` | XSS | Machine Learning | 2 |
| `command`| Command Injection | 2 |
| `hpp` | HTTP Parameter Polution | 2 |

> Note: `spoofing` module refers to "Host" header validation

**`VERBOSE`**
| Value | Messages displayed |
| - | - |
| 0 | Start, Stop, Configuration load status |
| 10+ | Configuration loading details, XSS model load status, Logging process status, Attacks detection |
| 100+ | Configuration details |

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
| `qs_values` | Qyery String value |
| `post_variables` | Posted data variable name |
| `post_values` | Posted data value |
| `json_keys` | JSON key name |
| `json_values` | JSON key value |

## Contacts
Renaud Bidou - renaud@paracyberbellum.io










