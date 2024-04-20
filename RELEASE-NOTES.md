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