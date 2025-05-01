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
