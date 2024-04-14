<h1>Python RASP</h1>

<p>
    <img src="https://img.shields.io/badge/Version-0.6.0-green?style=for-the-badge" alt="version 0.6.0"/>
    <a href="https://www.paracyberbellum.io">
        <img src="https://img.shields.io/badge/A%20project%20by-ParaCyberBellum-blue?style=for-the-badge" alt="A project by ParaCyberBellum"/>
    </a>
    <a href="https://twitter.com/ParaCyberBellum">
        <img src="https://img.shields.io/badge/Twitter-@ParaCyberBellum-yellow?style=for-the-badge&color=666666" alt="@ParaCyberBellum on Twitter"/>
    </a>
</p>

> Check [PyRASP Release Notes](https://github.com/rbidou/pyrasp/blob/main/RELEASE-NOTES.txt)

- [0. Overview](#0-overview)
  - [Security Modules](#security-modules)
  - [Supported Frameworks](#supported-frameworks)
- [1. Install](#1-install)
  - [From PyPi (Recommended)](#from-pypi-recommended)
  - [From Source](#from-source)
  - [AWS Lambda](#aws-lambda)
- [2. Run](#2-run)
  - [Classes](#classes)
  - [Flask \& FastAPI](#flask--fastapi)
    - [Guidelines](#guidelines)
    - [Examples](#examples)
  - [Django](#django)
    - [Guidelines](#guidelines-1)
    - [Examples](#examples-1)
  - [AWS Lambda](#aws-lambda-1)
    - [Guidelines](#guidelines-2)
    - [Examples](#examples-2)
  - [Environment Variables](#environment-variables)
  - [Startup](#startup)
- [3. Configuration](#3-configuration)
  - [Example File](#example-file)
  - [Parameters](#parameters)
    - [Generic Parameters Table](#generic-parameters-table)
    - [Default ignore paths](#default-ignore-paths)
    - [Default decoy paths](#default-decoy-paths)
  - [Specific Parameters Values](#specific-parameters-values)
    - [`SECURITY_CHECKS`](#security_checks)
    - [Default security checks values](#default-security-checks-values)
    - [`VERBOSE`](#verbose)
- [4. Event Logs Format](#4-event-logs-format)
  - [Logs Data](#logs-data)
  - [JSON Logs](#json-logs)
  - [Syslog Logs](#syslog-logs)
  - [Attack Types](#attack-types)
  - [Payload Locations](#payload-locations)
- [5. Cloud Operations](#5-cloud-operations)
  - [Run](#run)
    - [Flask \& FastAPI](#flask--fastapi-1)
    - [Django](#django-1)
    - [AWS Lambda](#aws-lambda-2)
    - [Environment Variables](#environment-variables-1)
  - [Configuration download](#configuration-download)
    - [Overview](#overview)
    - [Format](#format)
    - [Configuration example](#configuration-example)
- [6. Status, Telemetry, Configuration \& Blacklist updates](#6-status-telemetry-configuration--blacklist-updates)
  - [Configuration](#configuration)
  - [Request format](#request-format)
  - [Response format](#response-format)
    - [Configuration updates](#configuration-updates)
    - [Blacklist updates](#blacklist-updates)
- [7. Addendum: AWS Lambda Specificities](#7-addendum-aws-lambda-specificities)
  - [Settings](#settings)
    - [Memory](#memory)
  - [Timeout](#timeout)
  - [Limitations](#limitations)
    - [Function code size](#function-code-size)
    - [Beacons](#beacons)
    - [Latency](#latency)
    - [Logs](#logs)
  - [The PyRASP Layer](#the-pyrasp-layer)
    - [Content](#content)
    - [Available Layers](#available-layers)
- [8. Contacts](#8-contacts)

# 0. Overview
`pyrasp` is a **Runtime Application Self Protection** package for Python-based Web Servers. It protects against the main attacks web applications are exposed to, from within the application. It is also capable of providing basic telemetry such as cpu and memory usage and requests count.

It can operate using a local configuration file or get it from a remote/cloud server. Logs and telemetry (optional) can be sent to remote servers as well, and threats information can be shared across agents.

One specificity of `pyrasp` relies on the fact that it does not use signatures. Instead it will leverage decoys, thresholds, system and application internals, machine learning and grammatical analysis.

## Security Modules
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
| Data Leak Prevention | Regexp | Blocks outgoing sensible data |

## Supported Frameworks
`pyrasp` 0.6.x supports Flask, FastAPI, Django and Python AWS Lambda functions

> **IMPORTANT** FastAPI support requires `starlette` >= 0.28.0

# 1. Install

> See specific section for AWS Lambda functions

## From PyPi (Recommended)
```
pip install pyrasp
```
## From Source
```
git clone https://github.com/rbidou/pyrasp
cd pyrasp
pip install -r requirements.txt
```

## AWS Lambda
You need to add a specific layer to your AWS function. See related [AWS Lambda documentation](https://docs.aws.amazon.com/lambda/latest/dg/adding-layers.html).
<br>During the layer installation, select "Custom Layer".
<br>Several options are available for the layers, see [Available Layers](https://github.com/rbidou/pyrasp/blob/main/LAMBDA-LAYERS.md) and provide the ARN of the layer you want to use.

> It is recommended to use the  the `PyRASP-Full` layer.

# 2. Run

## Classes

| Framework | `rasp_class` | Note |
| - | - | - |
| Flask | FaskRASP | |
| FastAPI | FastApiRASP | **IMPORTANT** Requires starlette >= 0.28.0 |
| Django | DjangoRASP | |
| AWS Lambda | LambdaRASP | See (Addendum)[#7-addendum-aws-lambda-specificities] for limitations & specificities |

## Flask & FastAPI

### Guidelines

`pyrasp` requires 2 lines of code to run.

`from pyrasp.pyrasp import <rasp_class>`

<ins>Local Agent</ins>

`<rasp_class>(<framework_instance>, conf = <configuration_file>)`


<ins>Cloud Agent</ins>

> See [Cloud Operations](#cloud-operations) section for details

`<rasp_class>(<framework_instance>, cloud_url = <configuration_url>, key = <agent_key>)`

### Examples

```python
from pyrasp.pyrasp import FlaskRASP

app = Flask(__name__)
FlaskRASP(app, conf = 'rasp.json')
```

```python
from pyrasp.pyrasp import FastApiRASP
app = FastAPI()
rasp = FastApiRASP(app, cloud_url = 'https://pyrasp.my.org/config', key = '000000-1111-2222-3333-44444444')
```

## Django

### Guidelines

The `pyrasp` class must be added to the `MIDDLEWARE` variable in the `settings.py` file of the Django application.
A `PYRASP_CONF` variable must be added to the same file. It contains the path of the configuration file.
For cloud deployment `PYRASP_CLOUD_URL` and `PYRASP_KEY` variables must be set. (See [Cloud Operations](#cloud-operations) section for details)

### Examples

```python
PYRASP_CONF = 'rasp.json'

MIDDLEWARE = [
    'pyrasp.pyrasp.DjangoRASP',
    ...
]
```

```python
PYRASP_CLOUD_URL = 'https://pyrasp.my.org/config'
PYRASP_KEY = '000000-1111-2222-3333-44444444'

MIDDLEWARE = [
    'pyrasp.pyrasp.DjangoRASP',
    ...
]
```

## AWS Lambda

### Guidelines

The `pyrasp` module must be imported `from pyrasp.pyrasp import <rasp_class>`.

A decorator must be added on top of the lambda function handler.

<ins>Local Agent</ins>

`@LambdaRASP(conf = <configuration_file>)`


<ins>Cloud Agent</ins>

> See [Cloud Operations](#cloud-operations) section for details

`@LambdaRASP(cloud_url = <configuration_url>, key = <agent_key>)`

### Examples

```python
@LambdaRASP(conf = 'rasp.json').register
def lambda_handler(event, context):
...
```

```python
@LambdaRASP(cloud_url = 'https://pyrasp.my.org/config', key = '000000-1111-2222-3333-44444444').register
def lambda_handler(event, context):
...
```

## Environment Variables

`cloud_url`, `key` and `conf` values can be set as environment variables:
- `PYRASP_CLOUD_URL`: URL to retrieve agent configuration from
- `PYRASP_KEY`: unique key to identify the agent 
- `PYRASP_CONF`: configuration file path

## Startup
At startup of the application `pyrasp` loading information is displayed.

```
### PyRASP v0.6.0 ##########
[+] Starting PyRASP
[+] Loading configuration from rasp.json
[+] XSS model loaded
[+] SQLI model loaded
[+] PyRASP succesfully started
############################
```

# 3. Configuration
Configuration is set from a JSON file.
> `pyrasp` first loads default values and overwrite data from configuration.

> If configuration is loaded from a remote server, the response body to the request should be a JSON containing a valid pyrasp configuration file as described below.
## Example File
```json
{
    "config": {
        "HOSTS" : ["mysite.mydomain.com"],
        "APP_NAME" : "Web Server",
        "GTFO_MSG" : "<html><head /><body><h1>You have been blocked</h1></body></html>",
        "DENY_STATUS_CODE": 403,
    
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
            "command": 2,
            "dlp": 2
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
    
        "DLP_PHONE_NUMBERS": false,
        "DLP_CC_NUMBERS": false,
        "DLP_PRIVATE_KEYS": false,
        "DLP_HASHES": false,
        "DLP_WINDOWS_CREDS": false,
        "DLP_LINUX_CREDS": false,
    
        "LOG_ENABLED": false,
        "LOG_FORMAT": "Syslog",
        "LOG_SERVER": "127.0.0.1",        
        "LOG_PORT": 514,    
        "LOG_PROTOCOL": "UDP",
        "LOG_PATH": "",
        "RESOLBVE_COUNTRY": false,
    
        "CHANGE_SERVER": true,
        "SERVER_HEADER": "Apache",
    
        "BEACON": false,
        "TELEMETRY_DATA": false,
        "BEACON_URL": "",
        "BEACON_DELAY": 30
    }
}
```
## Parameters
### Generic Parameters Table
| Parameter | Type | Values | Default | Usage |
| - | - | - | - | - |
| `HOSTS` | list of strings | any | `[]` | List of valid 'Host' headers checked for spoofing detection |
| `APP_NAME` | string | any | `["Web Server"]` | Identification of the web application in the logs |
| `GTFO_MSG` | string | any | `["Blocked"]` | Message displayed when request is blocked. HTML page code is authorized |
| `DENY_STATUS_CODE` | integer | any | `403` | HTTP status code sent in response to blocked requests | 
| `VERBOSE` | integer | any | `0` | Verbosity level - See [Specific Parameters Values](#specific-parameters-values) |
| `DECODE_B64` | boolean | true, false | `true` | Decode Base64-encoded payloads |
| `SECURITY_CHECKS` | integer |  0, 1, 2, 3 | see below | Security modules status - See [Specific Parameters Values](#specific-parameters-values)  |
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
| `DLP_PHONE_NUMBERS` | boolean | true, false | `false` | Check phone number leak |
| `DLP_CC_NUMBERS` | boolean | true, false | `false` | Check credit card number leak |
| `DLP_PRIVATE_KEYS` | boolean | true, false | `false` | Check private key leak |
| `DLP_HASHES` | boolean | true, false | `false` | Check hash leak |
| `DLP_WINDOWS_CREDS` | boolean | true, false | `false` | Check Windows credentials leak |
| `DLP_LINUX_CREDS` | boolean | true, false | `false` | Check Linux credentials leak |
| `LOG_ENABLED` | boolean | true, false | `false` | Enable event logging |
| `LOG_FORMAT` | string | syslog, json | `"syslog"` | Format of event log - see [Event Logs Format](#4-event-logs-format) |
| `LOG_SERVER` | string | any | `"127.0.0.1"` | Log server IP address or FQDN |
| `LOG_PORT` | integer | 1 - 36635 | `514` | Log server port |
| `LOG_PROTOCOL` | string | tcp, udp, http, https | `"udp"` | Log server protocol (tcp or udp for syslog, http or https for json) |
| `LOG_PATH` | string | any | `""` | URL path to use for http(s) log webhook (ex: /logs) |
| `RESOLVE_COUNTRY` | boolean | true, false | `true` | Resolve country of attack source IP address |
| `CHANGE_SERVER` | boolean | true, false | `true` | Change response "Server" header |
| `SERVER_HEADER` | string | any | `"Apache"` | Message displayed when request is blocked. HTML page code is authorized |

### Default ignore paths
```json
"IGNORE_PATHS" : ["^/favicon.ico$","^/robots.txt$","^/sitemap\\.(txt|xml)$"]
```

### Default decoy paths
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

## Specific Parameters Values
### `SECURITY_CHECKS`
| Value | Usage |
| - | - |
| 0 | Disabled |
| 1 | Enabled, no Blacklisting |
| 2 | Enabled, Blacklisting activated |

### Default security checks values
| Parameter | Function | Default Value |
| - | - | - |
| `flood` | Flood & Brute Force | 2 |
| `headers`| Forbidden Headers | 0 | 
| `path` | Requests Validation | 1 | 
| `spoofing`| Spoofing | 0 |
| `decoy`| Decoy | 2 |
| `sqli`| SQL Injection | 2 |
| `xss` | XSS | 2 |
| `command`| Command Injection | 2 |
| `hpp` | HTTP Parameter Polution | 2 |
| `dlp` | Data Leak Prevention | 0 |

> Note: `spoofing` module refers to "Host" header validation

### `VERBOSE`
| Value | Messages displayed |
| - | - |
| 0 | Start, Stop, Configuration load status |
| 10+ | Configuration loading details, XSS model load status, Logging process status, Attacks detection |
| 100+ | Configuration details |

# 4. Event Logs Format
## Logs Data
| Parameter | Format | Detail |
| - | - | - |
| `<event_time>` | %Y/%m/%d %H:%M:%S | Time on the system running `pyrasp` |
| `<application_name>` | string | Value of the `APP_NAME` parameter |
| `<event_type>` | string | Type of attack - see (Attack Types)[#attack-types] section below |
| `<source_ip>` | string | IP address of the attack source |
| `<country>` | string | Country of the source address ("Private" if internal network), requires `RESOLVE_COUNTRY` option set |
| `<location>` | string | Location of the offending payload - See (Payload Locations)[#payloads-locations] section below |
| `<payload>` | string | Suspicious payload (base64 decoded) |

## JSON Logs
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

## Syslog Logs
```
[<event_time>] "<application_name>" - "<event_type>" - "<source_ip>" - "<country>" - "<location>:<payload>"
```

## Attack Types
| Value | Attack Type |
| - | - |
| `blacklist`| Blacklisted IP |
| `path`| Invalid Path |
| `flood`| Flood |
| `spoofing` | Host Spoofing |
| `decoy` | Decoyed Request |
| `format` | Format Mismatch |
| `sqli` | SQL Injection |
| `xss`| XSS |
| `hpp` | Parameter Pollution |
| `command` | Command Injection |
| `headers` | Forbidden Header |
| `dlp` | Data Leak Prevention |

## Payload Locations
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
| `content` | Response content |

# 5. Cloud Operations
`pyrasp` is capable to operate in a 'cloud' environment:
- Retrieve initial configuration and updates from remote server
- Retrieve Blacklist from remote server at startup
- Provide regular agent status to remote server
- Provide basic telemetry (cpu & memory usage, number of requests)
- Share new blacklisted entries
- Update blacklist with new entries provided by remote server

## Run

### Flask & FastAPI

`pyrasp` instance creation requires 2 specific arguments:
- `cloud_url`: URL to retrieve agent configuration from
- `key`: unique key to identify the agent 

`<rasp_class>(<framework_instance>, cloud_url = <configuration_url>, key = <agent_key>)`

> Those 2 parameters can be set as environment vaiables  - see [Environment Variables](#environment-variables-1)


```python
from pyrasp.pyrasp import FastApiRASP
app = FastAPI()
rasp = FastApiRASP(app, cloud_url = 'https://pyrasp.my.org/config', key = '000000-1111-2222-3333-44444444' )
```

### Django

For cloud agents, `PYRASP_CLOUD_URL` and `PYRASP_KEY` variables must be added to the `settings.py` file of the Django application:
- `PYRASP_CLOUD_URL` contains the URL to retrieve agent configuration from
- `PYRASP_KEY` is used by the server to uniquely identify the agent.


```python
PYRASP_CLOUD_URL = 'https://pyrasp.my.org/config'
PYRASP_KEY = '000000-1111-2222-3333-44444444'

MIDDLEWARE = [
    'pyrasp.pyrasp.DjangoRASP',
    ...
]
```

### AWS Lambda

`pyrasp` instance creation requires 2 specific arguments:
- `cloud_url`: URL to retrieve agent configuration from
- `key`: unique key to identify the agent 

`@LambdaRASP(cloud_url = <configuration_url>, key = <agent_key>)`

> Those 2 parameters can be set as environment variables - see [Environment Variables](#environment-variables-1)

```python
@LambdaRASP(cloud_url = 'https://pyrasp.my.org/config', key = '000000-1111-2222-3333-44444444').register
def lambda_handler(event, context):
...
```

### Environment Variables

`cloud_url` and `key` values can be set as environment variables:
- `PYRASP_CLOUD_URL`: URL to retrieve agent configuration from
- `PYRASP_KEY`: unique key to identify the agent 

## Configuration download
### Overview

Configuration file and blacklist are retrieved by the agent through a `GET` request to the URL specified.

At agent startup the remote configuration URL is displayed.
```
### PyRASP v0.6.0 ##########
[+] Starting PyRASP
[+] Loading default configuration
[+] Loading configuration from http://pyrasp.my.org/config
[+] XSS model loaded
[+] SQLI model loaded
[+] Starting logging process
[+] Starting beacon process
[+] PyRASP succesfully started
############################
```

### Format

The response to the request **MUST** be an `application/json` body containing the configuration.
<br>The data structure **MUST** be a dictionary (`{}`)

The JSON configuration **MUST** be provided in the `config` key.
<br>Optionaly an initial blacklist can be provided as a dictionary structure in the `blacklist` key of the response.
<br>The blacklist structure **MUST** comply with the format detailed in the example below.

### Configuration example

```json
{
    "config": {
        "HOSTS" : ["mysite.mydomain.com"],
        "APP_NAME" : "Web Server",
        "GTFO_MSG" : "<html><head /><body><h1>You have been blocked</h1></body></html>",
        "DENY_STATUS_CODE": 403,
        ...
    },
    "blacklist": {
        "<ip_address>": <detection_epoch_time>,
        ...
    }
}
```

# 6. Status, Telemetry, Configuration & Blacklist updates
## Configuration
Agent can be configured to regularly send status, telemetry and new blacklist entries to a remote server. 

This feature is enabled by setting the `BEACON` configuration parameter to `true`.
<br>The `BEACON_URL` parameter **MUST** be set. It defines the URL to which beacon requests will be sent.
<br>The number of seconds between 2 beacon requests is defined by the `BEACON_DELAY` parameter. The default value ios set to `30` seconds.

If the `TELEMETRY_DATA` parameter is set to `true` cpu and memory average usage, as well as the count of succesfull, error and attack requests are sent to the remote server.

If the `BLACKLIST_SHARE` paremeter is set to `true` new blacklist entries will be sent to the remote server.

The parameters to be set in the configuration files are listed in the table below.
| Parameter | Type | Values | Default | Usage |
| - | - | - | - | - |
| `BEACON` | boolean | true, false | `false` | Enable status beacon to management server |
| `BEACON_URL` | string | URL | `""` | URL to send status data |
| `BEACON_DELAY` | integer | any | `30` | Number of seconds between each beacon |
| `TELEMETRY_DATA` | boolean | true, false | `false` | Add telemetry data (cpu, memory, request count) to status beacon |
| `BLACKLIST_SHARE` | boolean | true, false | `false` | Share blacklist entries with other agents (cloud only) |

## Request format
Data is sent to the remote server as a `POST` request to the URL provided in the `BEACON_URL` configuration parameter. Body of the request is a JSON structure detailed below.

1. Default beacon request
```json
{ 
    "key": "<agent-key>", 
    "version": "<agent-version>",
}
```

2. Beacon request with telemetry
> This request is sent to the remote server if the `TELEMETRY_DATA` parameter is set to `true`
```json
{ 
    "key": "<agent-key>", 
    "version": "<agent-version>",
    "telemetry": {
        "cpu": <cpu_usage_percent>, 
        "memory": <memory_usage_percent>,
        "requests": {
            "success": <successful_requests_count>,
            "error": <error_requests_count>,
            "attacks": <attacks_requests_count>
        }
    }
}
```

3. Beacon request with blacklist updates
> This request is sent to the remote server if the `BLACKLIST_SHARE` parameter is set to `true`
```json
{ 
    "key": "<agent-key>", 
    "version": "<agent-version>",
    "blacklist": [
        [ "<ip_address>", <detection_epoch_time> ],
        ...
    ]
}
```

## Response format
Response to beacon requests **MUST** be in an `application/json` format. 
<br>The data structure **MUST** be a dictionary (`{}`)
- If a configuration update is required, it **MUST** be located in the `config` key
- If a Blacklist update is required,  it **MUST** be located in the `blacklist` key

### Configuration updates

Configuration updates **MUST** be provided in the `config` key of the response data structure, containing the new configuration.

```json
{
    "config": {
        "HOSTS" : ["mysite.mydomain.com"],
        "APP_NAME" : "Web Server",
        "GTFO_MSG" : "<html><head /><body><h1>You have been blocked</h1></body></html>",
        "DENY_STATUS_CODE": 403,
        ...
    }
}
```

### Blacklist updates

Blacklist updates **MUST** be provided in a structure located in the `blacklist` key of the beacon response.
<br>The structure **MUST** contain 2 keys:
- `new`: list of new IP addresses to be added to the blacklist
- `remove`: list of IP addresses to be removed from the blacklist

```json
{
    "blacklist": {
        "new": [ "<ip_address>", ... ],
        "remove": [ "<ip_address>", ... ]
    }
}
```

# 7. Addendum: AWS Lambda Specificities

Due to AWS Lambda concept of ephemeral containers, `pyrasp` behavior is slighlty different and has a few limitations compared to other platforms.
<br>Specific settings must also be applied in the Lambda function configuration.

## Settings

> Machine Learning engines are quite resource intensive and require specific configuration settings

### Memory
`pyrasp` requires additional memory to run with the lambda function. This is mostly due to the machine learning engines (and related libraries) used for XSS and SQL Injection detection. 
<br>If XSS or SQL Injection detections are enabled, an **additional 165MB of memory** must be added to the Lambda function configuration. (See related [AWS Lambda documentation](https://docs.aws.amazon.com/lambda/latest/dg/configuration-memory.html))

## Timeout
The `pyrasp` XSS and SQL Injection machine learning engines are loaded at the Lambda function startup, noticeably increasing the overall startup time (~5 seconds).
<br>If XSS or SQL Injection detections are enabled, the Lambda function timeout must be increased by **minimum 5 seconds** (See related [AWS Lambda documentation](https://docs.aws.amazon.com/lambda/latest/dg/configuration-timeout.html))

## Limitations

### Function code size
AWS Lambda total code size (including layers) has a limit of 250MB. PyRASP layer size is 80MB, limiting the rest of the function code to 170MB.

### Beacons
Beacon is implemented in a different way for in `pyrasp` for Lambda functions for 2 reasons: multithreading is not supported and containers are ephemeral.

Consequently beacons are sent in 2 specific cases:
- At agent startup
- When a request is received and the last beacon was sent in a time period graeter than the value specified in the `BEACON_DELAY`  parameter

Therefore, on low traffic functions, monitoring may report agents as down while they remain active (but didn't process any request in the `BEACON_DELAY` timeframe).

### Latency
With all security modules enabled, the processing of a request doesn't add noticeable latency.
<br>However, when the lambda instance is in "cold" state (meaning the container needs to be restarted), the processing of the request requires restart of the `pyrasp` module. This adds about 5 seconds latency to the global processing if the request.

### Logs
As threads are not supported in AWS Lambda environment, country of source IP is not resolved, this prevents from additional latency in the requests processing. The field in logs is set to an empty string. 

## The PyRASP Layer

### Content
The AWS Lambda layer required to run the `pyrasp` module is about 80 MB size and contains the modules listed below.
- sqlparse
- scikit-learn==1.3.0
- requests
- psutil
- certifi
- charset_normalizer
- idna
- joblib
- numpy
- scikit-learn
- scipy
- urllib3
- threadpoolctl
- pyrasp

If some modules are already loaded from another layer, it is possible to rebuild a custom PyRASP layer to lower its size (See related [AWS Lambda documentation](https://docs.aws.amazon.com/lambda/latest/dg/python-package.html#python-package-create-dependencies)).

### Available Layers
Several layers are made available to allow custom deployment. 
<br>It is strongly recommended to use the latest version, at least in the beta stage (version 0.x.x). But is up to you...
<br>See the list of [Available Layers](https://github.com/rbidou/pyrasp/blob/main/LAMBDA-LAYERS.md)


# 8. Contacts
Renaud Bidou - renaud@paracyberbellum.io










