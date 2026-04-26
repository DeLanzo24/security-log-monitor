"""
Automated Security Log Monitoring and MITRE ATT&CK Mapping Tool
Author: DeLanzo Sharp

This script reads a static security log file, detects suspicious events,
maps those events to MITRE ATT&CK techniques, and writes a readable alert report.
"""

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any


FAILED_LOGIN_THRESHOLD = 3


def load_mitre_mapping(mapping_path: Path) -> Dict[str, Dict[str, str]]:
    """Load MITRE ATT&CK mapping data from a JSON file."""
    try:
        with mapping_path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError as error:
        raise FileNotFoundError(f"MITRE mapping file not found: {mapping_path}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"MITRE mapping file is not valid JSON: {mapping_path}") from error


def read_logs(log_path: Path) -> List[str]:
    """Read log lines from a text file and remove empty lines."""
    try:
        with log_path.open("r", encoding="utf-8") as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError as error:
        raise FileNotFoundError(f"Log file not found: {log_path}") from error


def extract_source_ip(log_line: str) -> str:
    """Extract the first IPv4 address from a log line, if one exists."""
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log_line)
    return ip_match.group(0) if ip_match else "unknown"


def extract_username(log_line: str) -> str:
    """Extract a username from common log patterns."""
    user_match = re.search(r"user\s+([A-Za-z0-9_.-]+)", log_line, re.IGNORECASE)
    return user_match.group(1) if user_match else "unknown"


def build_alert(log_line: str, rule_name: str, mapping: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
    """Create a standardized alert dictionary for a detected event."""
    rule_details = mapping[rule_name]
    return {
        "timestamp_detected": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "rule": rule_name,
        "severity": rule_details["severity"],
        "mitre_technique_id": rule_details["technique_id"],
        "mitre_technique_name": rule_details["technique_name"],
        "mitre_tactic": rule_details["tactic"],
        "description": rule_details["description"],
        "source_ip": extract_source_ip(log_line),
        "username": extract_username(log_line),
        "original_log": log_line,
    }


def detect_suspicious_events(log_lines: List[str], mapping: Dict[str, Dict[str, str]]) -> List[Dict[str, Any]]:
    """
    Detect suspicious events using keyword and pattern matching.

    This project uses simple rule-based detection so the logic is easy to follow.
    In a production environment, these rules could be expanded with regex patterns,
    event IDs, structured JSON logs, or SIEM queries.
    """
    alerts = []
    failed_login_tracker = defaultdict(int)

    for line in log_lines:
        lower_line = line.lower()

        if "failed login" in lower_line:
            alerts.append(build_alert(line, "FAILED_LOGIN", mapping))
            username = extract_username(line)
            source_ip = extract_source_ip(line)
            failed_login_tracker[(username, source_ip)] += 1

        if "powershell" in lower_line or "executionpolicy bypass" in lower_line:
            alerts.append(build_alert(line, "POWERSHELL_EXECUTION", mapping))

        if "new user created" in lower_line:
            alerts.append(build_alert(line, "NEW_USER_CREATED", mapping))

        if any(keyword in lower_line for keyword in ["curl", "wget", ".exe", "download"]):
            alerts.append(build_alert(line, "SUSPICIOUS_DOWNLOAD", mapping))

        if "added to administrators" in lower_line or "privilege" in lower_line:
            alerts.append(build_alert(line, "PRIVILEGE_CHANGE", mapping))

    for (username, source_ip), count in failed_login_tracker.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            summary_log = (
                f"Multiple failed logins detected for user {username} "
                f"from {source_ip}. Count: {count}"
            )
            alerts.append(build_alert(summary_log, "MULTIPLE_FAILED_LOGINS", mapping))
            alerts[-1]["failed_login_count"] = count

    return alerts


def write_report(alerts: List[Dict[str, Any]], output_path: Path) -> None:
    """Write all alerts to a readable text report."""
    with output_path.open("w", encoding="utf-8") as report:
        report.write("Security Log Monitoring Alert Report\n")
        report.write("=" * 44 + "\n\n")
        report.write(f"Total Alerts Generated: {len(alerts)}\n")
        report.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        if not alerts:
            report.write("No suspicious events were detected.\n")
            return

        for alert_number, alert in enumerate(alerts, start=1):
            report.write(f"Alert #{alert_number}\n")
            report.write("-" * 20 + "\n")
            report.write(f"Rule: {alert['rule']}\n")
            report.write(f"Severity: {alert['severity']}\n")
            report.write(f"Username: {alert['username']}\n")
            report.write(f"Source IP: {alert['source_ip']}\n")
            report.write(
                f"MITRE ATT&CK: {alert['mitre_technique_id']} - "
                f"{alert['mitre_technique_name']}\n"
            )
            report.write(f"Tactic: {alert['mitre_tactic']}\n")
            report.write(f"Description: {alert['description']}\n")
            if "failed_login_count" in alert:
                report.write(f"Failed Login Count: {alert['failed_login_count']}\n")
            report.write(f"Original Log: {alert['original_log']}\n\n")


def main() -> None:
    """Parse command-line arguments and run the log monitoring workflow."""
    parser = argparse.ArgumentParser(
        description="Detect suspicious security events and map them to MITRE ATT&CK."
    )
    parser.add_argument("--logs", default="sample_logs.txt", help="Path to the log file to analyze.")
    parser.add_argument("--mapping", default="mitre_mapping.json", help="Path to the MITRE mapping JSON file.")
    parser.add_argument("--output", default="alerts_report.txt", help="Path for the generated alert report.")
    args = parser.parse_args()

    log_path = Path(args.logs)
    mapping_path = Path(args.mapping)
    output_path = Path(args.output)

    mapping = load_mitre_mapping(mapping_path)
    log_lines = read_logs(log_path)
    alerts = detect_suspicious_events(log_lines, mapping)
    write_report(alerts, output_path)

    print("Security log monitoring completed successfully.")
    print(f"Analyzed log entries: {len(log_lines)}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"Report saved to: {output_path}")


if __name__ == "__main__":
    main()
