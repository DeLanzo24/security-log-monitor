# Automated Security Log Monitoring and MITRE ATT&CK Mapping Tool

**Author:** DeLanzo Sharp  
**Course:** Security Automation  
**Repository:** https://github.com/DeLanzo24/security-log-monitor

## Project Overview

This project is a Python-based security automation tool that reviews a sample security log file, detects suspicious activity, and maps those detections to the MITRE ATT&CK framework. The goal of the project is to show how basic automation can help identify security events faster than manually reviewing logs line by line.

The tool is designed to be simple enough to understand, but structured enough to reflect real-world security concepts such as log monitoring, alerting, severity assignment, and MITRE ATT&CK mapping.

## Features

- Reads security events from a static log file
- Detects suspicious activity using rule-based logic
- Identifies failed login attempts
- Detects multiple failed logins from the same user and IP address
- Flags PowerShell execution
- Detects new user account creation
- Flags suspicious downloads
- Detects privilege or administrator group changes
- Maps alerts to MITRE ATT&CK techniques and tactics
- Generates a readable alert report in text format

## Project Files

```text
security-log-monitor/
│-- log_monitor.py
│-- sample_logs.txt
│-- mitre_mapping.json
│-- alerts_report.txt
│-- README.md
│-- requirements.txt
│-- screenshots/
```

## Dependencies

This project only uses Python standard library modules, so no third-party packages are required.

Recommended version:

```text
Python 3.10 or newer
```

## Setup Instructions

1. Clone or download the repository.
2. Open the project folder in VS Code or another code editor.
3. Make sure Python is installed.
4. Open a terminal in the project folder.
5. Run the script:

```bash
python log_monitor.py
```

The script will analyze `sample_logs.txt` and create or update `alerts_report.txt`.

## Optional Command-Line Usage

You can also provide custom file names:

```bash
python log_monitor.py --logs sample_logs.txt --mapping mitre_mapping.json --output alerts_report.txt
```

## Example Output

```text
Security log monitoring completed successfully.
Analyzed log entries: 12
Alerts generated: 11
Report saved to: alerts_report.txt
```

## MITRE ATT&CK Mapping Examples

| Detection | MITRE Technique | Tactic | Severity |
|---|---|---|---|
| Failed login | T1110 - Brute Force | Credential Access | Medium |
| Multiple failed logins | T1110 - Brute Force | Credential Access | High |
| PowerShell execution | T1059.001 - PowerShell | Execution | High |
| New user created | T1136 - Create Account | Persistence | High |
| Suspicious download | T1105 - Ingress Tool Transfer | Command and Control | Medium |
| Privilege change | T1098 - Account Manipulation | Persistence | High |

## Security Note

This project does not use API keys or sensitive credentials. If future versions are expanded to use threat intelligence APIs or cloud services, API keys should be stored in environment variables and never committed to GitHub.

## Future Improvements

Future versions could include support for structured JSON logs, Windows Event IDs, email alerts, CSV exports, a dashboard, or integration with a SIEM platform.
