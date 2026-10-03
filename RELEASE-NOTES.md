# 0.10.0

## READ THE DOC !!!
- Moved to a modular architecture, 1 class per python module
- Import must be refactored in the code (ex: `from pyrasp.pyrasp import FlaskRASP` -> `from pyrasp.flaskrasp import FlaskRASP` )
- Kept backward compatibility as people usually don't read the doc...

## New features
- Support for aiohttp framework
- Support for generic WSGI gateway covering Bottle, Pyramid, CherryPy, web2py, and Falcon-WSGI frameworks
- Support for generic ASGI gateway covering Litestar, BlackSheep, Quart, Sanic-ASGI, Connexion, mounted MCP transports, Gradio/Chainlit frameworks

## Improvements

### Documentation
- New documentation, with global workflow, security modules details, use cases, etc.

### Detection
- Added detection for query string and posted body variables names
- Added detection for JSON keys
- Improved detection for vectors containing JSON 
- DLP engine now processes full streamed responses
- Improved flood detection accuracy 
- Added additional invisible characters: hangul fillers, braille blank and Khmer vowels
- Detection for suspicious invisible and cyrillic characters in cookies and headers
- Added XSS and suspicious characters detection to MCP Tools agent
- Added XSS, SQL injections and suspicious characters detection to User-Agent and Referer headers

### UI
- Startup display PyRASP platform (ex: `[+] Starting PyRASP: WSGI`)

### Core
- Modular architecture for faster startup and easier maintenance
- Each agent now imports only its own framework, so PyRASP no longer tries to load Flask, FastAPI, Django, Azure and FastMCP at startup.
- `torch`, `tiktoken` and the GPT model are now loaded only when prompt injection detection is enabled, which cuts startup time and serverless cold starts.
- Removed unused imports and data constants
- Simplified the threading imports, dropping the platform-dependent conditional import and the redundant local import in the constructor.
- `GcpRASP` now inherits `build_block_response` and `build_redirect_response` from `FlaskRASP` instead of duplicating them.
- Backward compatibility: `from pyrasp.pyrasp import FlaskRASP` (and the other agents) still works through lazy loading.
- Configurations generation and updates through beacons improved, read the Chapter 3. of the doc

### Agents
- Asynchronous mode support for MCP agent
- Cloud agent beacon mechanism code factoring
- Azure agent now supports file upload validation

## Bug fix
- Fixed multiple JA4H fingerprint issues in Azure agent
- `PYRASP_CONF` environment variable was never used...
- Cloud configuration didn't use specified template.
- `LOG_PATH` was not applied to webhook, always logging to `/logs`
- The UDP and TCP code paths were swapped in syslog transport
- Removed `CHARS_UNICODE_TAGS` check, generating a 100% false-positive score
- Fixed unicode decoding in specific cases
- Fixed FastAPI and Django `X-Forwarded-For` header collection for source IP
- Fixed hash DLP regular expression
- Fixed TCP syslog: the socket was closed after the first log, and a str was sent instead of bytes
- DLP label for hash leaks was `Private Key` fixed to `Password Hash` 
- API `get_status()` always returned `Default`
- Django module JSON parsing fix
- Fixed exceptions mechanism that would trigger detection in some specific cases
- Fixed HPP detection in Azure functions
- Header whitelisting in FastAPI agent just didn't work. 

# 0.9.4

## New features
- New suspicious characters class: Unicode Tags (\u0000-\u007F), set with the `CHARS_UNICODE_TAGS` parameters
- DLP filters for cloud, repositories and AI providers API key 
- Bot Detection, based of JA4H fingerprint

## Improvements
- `unicode_escape` codex depreciation handled with homemade function
- Improved multipart files upload processing to prevent memory-based DoS

## Bug Fix
- Configuration update in cloud architecture was broken since 0.9.2... Bug fixed, QA team fired, again. 
- Some documentation fixes

# 0.9.3

## New features
- Suspicious characters detection (Cyrillic lookalike, ASCII non-printable, invisible)
- JA4H fingerprint added to attack detail (`LOG_JA4H_FINGERPRINT`, default to `false`)

## Improvements
- If cloud server not reachable at startup, agent falls back to default template configuration - wondering if it makes sense...
- Daemonized log thread for cleaner exit
- False-Positive in SQL injection detection engine fix
- Implemented `Flask.g`, simplifying FlaskRASP code

## Bug Fix
- Fixed FastAPI deprecation
- Fixed verbosity level initilialisation error
- SQLi injection engines error when handling non string content
- Agent would not start if cloud configuration is enabled and cloud server not reachable
- Error in multipart file analysis on FastAPI

# 0.9.2

## New features
- Configuration Templates
- Basic multipart file uploads validation for Flask and Django
- New reaction mechanism and capabilities

## READ THE DOC !!!
- Improved class constructor
- Changed configuration workflow
- `GTFO_MSG` and `DENY_STATUS_CODE` parameters have been deprecated (see `BLACKLIST_*` and `BLOCK_*` settings)

## Improvements
- Revamped reaction capabilities
- Simplified MCP blocked attack response format
- Improved posted variables processing in Flask
- Removed development mode
- New QA engine (ok that's on our side, but you benefit from it)

## Bug fix
- Fixed FastMCP deprecations
- Upgraded setuptools minimum version dependency to fix potential security issues

# 0.9.1

## New features
- Prompt Injection detection module based on custom 100% home made LLM
- Logging to local file

## Improvement
- Migrated from setuptools pkg_resources (deprecated) to importlib_resources (but who cares...)
- Log format is now independant from log protocol
- Simplified and cleaned some pieces of code

## Bug fix
- Fixed a FastAPI agent crash. Credits to Julien Balleyguier

# 0.9.0

## New features
- MCP Tools security

## Bug fix
- Exceptions were not applied on FastAPI

# 0.8.4

## New features
- HTTP Headers whitelist

## Improvements
- Improved XSS and SQL injections machine learning engines
- Upgraded to scikit-learn 1.6.0

## Limitations
- Version 0.8.4 is not available on AWS Lambda Functions
- Some SQL Injection attacks may be blocked as XSS attacks

## Bug fix
- 'ends' pattern check was not applied

# 0.8.3

## New features
- New XSS and SQL injection machine learning engines

## Improvements
- SQL Injection grammatical analysis was removed to improve performances and lower false-positive rate

## Bug fix
- XSS and SQL injection tests won't fail when model is not loaded
- Fix Base64 decoding, which was a little bit too invasive 
- Log only mode was sending empty response on Flask 

## Limitation
- Version 0.8.3 is not available on AWS Lambda Functions
- AWS Lambda support will be provided in next version 

# 0.8.2

## New feature
- Attack details display with verbose level = 100+

## Improvements
- Improved JSON data analysis recursion
- Lowered TCP logs connection timeout

## Bug fix
- Removed a debug output when analyzing json data
- Specific payloads may crash XSS detection engine
- Fixed an SQL Injection false positive
- Fixed requirements.txt for build from sources

# v0.8.1

## New features
- **Zero-Trust Application Access**

## Improvements
- Noticeably improved documentation by fixing typos, dead links, etc.

## Bug fix
- Fixed several issues in agents for AWS, GCP and Azure serverless functions
- XSS check would fail while testing very specific JSON content

## License
- License changed to **CC BY-NC-SA 4.0** (https://creativecommons.org/licenses/by-nc-sa/4.0/)

# v0.8.0
Broken dependencies - Removed

# v0.7.2

## New features
- Application routes are sent when first connecting to configuration server (cloud operations)
- New API functions:
  - set_config(): change configuration from the protected application
  - get_routes(): get routes defined in the applications

## Improvements
- Handling of nested base64-encoded JSON structures
- Added explicit versions in dependencies requirements

## Bug fix
- No security engine was activated when running with default configuration

# v0.7.1

## New features
- Added detection engine and machine learning score in SQLI and XSS attack logs
- Added request path in JSON security logs

## Improvements
- Improved JSON extraction from headers values
- Improved SQL injection grammatical analysis to prevent some false-positive
- Country identification in logs can be disabled via the RESOLVE_COUNTRY configuration option
- Leaked data can be logged by setting the DLP_LOG_LEAKED_DATA configuration option to True (default: False)

## Bug fix
- Some cookie values were not properly processed
- PyRASP would crash at launch if SQL injection or XSS protections are not activated

# v0.7.0

## New features
- PyRASP classes API

## Improvements
- **Improved ML engines for SQL Injection and XSS detection**
  - Default SQL Injection detection probabilities raised to 0.85
  - Default XSS detection probabilities raised to 0.70
- Attack payloads are now base64 encoded in logs

## Bug fix
- Flask agent was still processing page, even if attack was detected

# v0.6.2

## New features
- **Support for Azure Functions**

## Improvement
- Slightly improved SQL injection detection

## Bug fix
- Fixed XSS engine false positive with some large JSON data
- Disabled security checks would be handled according to default value 

## Misc
- Fixed few things in documentation

# v0.6.1

## New features
- **Support for Google Cloud Functions**
- "Log Only" mode for detections
- Added exceptions to properly manage false-positive
- Added Brute Force specific attack type (previously merged with Flood)


## Improvements
- Decoy routes can be defined as a pattern with specific match function (regex, starts with or contains)
- Added MITRE ATT&CK technique ID and PCB attack ID in logs
- Added action taken by PyRASP agent in logs
- Default security checks are loaded if missing from configuration file (see documentation for values)

## Bug fix
- Attack floods are not detected on AWS Lambda agent, each attack being blocked individually 
- Error floods were not detected if source IP was not blacklisted (which was totally nonsense)

# v0.6.0

## New features
- **Python AWS Lambda functions support**

## Improvements
- Option to disable source IP country resolution in logs
- Configuration file can be set by environment variable
- Table of content and hyperlinks in the documentation
- Offending source IP country resolution in logs is now optional (default to enabled for backward compatibility)

## Bug fix
- Offending source IPs were blackisted event if the SECURITY_CHECKS value was set to 1 (Enabled, no Blacklisting)
