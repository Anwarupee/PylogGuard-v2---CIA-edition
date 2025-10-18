"""
Syslog Parser
-------------
Parses general system log messages into structured Python dictionaries.

Supports:
- Auth logs (/var/log/auth.log, /var/log/secure)
- Kernel logs (/var/log/kern.log)
- Generic system events (/var/log/syslog)

CIA Classification:
- Confidentiality: Unauthorized access attempts, SSH failures, sudo misuse
- Integrity: File tampering, privilege escalation
- Availability: Service crashes, reboots, daemon failures
"""

import re
from datetime import datetime
from core.classifier import classify_log_entry

# Example syslog formats:
# "Oct  8 10:15:23 server sshd[2345]: Failed password for root from 192.168.1.10 port 22 ssh2"
# "Oct  8 10:16:01 server systemd[1]: Started Samba SMB Daemon."
# "Oct  8 10:18:00 server kernel: [  245.123456] eth0: link is down"

SYSLOG_REGEX = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$"
)

# Patterns for classification
FAILED_LOGIN_PATTERN = re.compile(r"Failed password for (?P<user>\S+) from (?P<ip>[\d\.]+)")
ACCEPTED_LOGIN_PATTERN = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>[\d\.]+)")
SUDO_PATTERN = re.compile(r"sudo: (?P<user>\S+) : (?P<action>.+)")
SERVICE_FAILURE_PATTERN = re.compile(r"(failed|error|crash|panic|segfault|oom)", re.IGNORECASE)
SERVICE_START_PATTERN = re.compile(r"Started|restarted|Reloaded|enabled", re.IGNORECASE)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}


def parse_syslog_line(line: str) -> dict | None:
    """Parse a single syslog line into a structured event."""
    match = SYSLOG_REGEX.match(line)
    if not match:
        return None

    data = match.groupdict()
    now = datetime.now()
    try:
        # Construct timestamp with current year (syslog omits it)
        month = MONTHS.get(data["month"], now.month)
        dt = datetime(now.year, month, int(data["day"]))
        time_parts = data["time"].split(":")
        dt = dt.replace(hour=int(time_parts[0]), minute=int(time_parts[1]), second=int(time_parts[2]))
        data["timestamp"] = dt.isoformat()
    except Exception:
        data["timestamp"] = f"{data['month']} {data['day']} {data['time']}"

    message = data["message"]

    # Extract event details
    event_type, event_meta = classify_syslog_event(message)
    data.update(event_meta)
    data["event_type"] = event_type
    data["source"] = "syslog"

    return classify_log_entry(data)


def classify_syslog_event(message: str) -> tuple[str, dict]:
    """
    Determine event type from syslog message content.
    Returns (event_type, extracted_info)
    """
    msg_lower = message.lower()
    meta = {}

    # Failed SSH or login attempt
    if match := FAILED_LOGIN_PATTERN.search(message):
        meta = match.groupdict()
        return "auth_failure", meta

    # Successful SSH login
    if match := ACCEPTED_LOGIN_PATTERN.search(message):
        meta = match.groupdict()
        return "login_success", meta

    # sudo misuse (potential Integrity issue)
    if match := SUDO_PATTERN.search(message):
        meta = match.groupdict()
        if "root" in meta.get("action", "") and "denied" in meta.get("action", ""):
            return "privilege_escalation_attempt", meta
        return "sudo_usage", meta

    # System or service failure (Availability)
    if SERVICE_FAILURE_PATTERN.search(message):
        return "service_failure", {"description": message}

    # Service started (normal)
    if SERVICE_START_PATTERN.search(message):
        return "service_start", {"description": message}

    # Kernel warnings or hardware issues
    if "kernel" in msg_lower and ("error" in msg_lower or "panic" in msg_lower):
        return "kernel_panic", {"description": message}

    # Disk full, OOM, or I/O errors (Availability)
    if any(x in msg_lower for x in ["no space", "i/o error", "out of memory", "disk full"]):
        return "resource_failure", {"description": message}

    # Default
    return "generic_event", {"description": message}


def parse_syslog_file(path: str) -> list[dict]:
    """Parse all lines in a syslog file."""
    results = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parsed = parse_syslog_line(line)
            if parsed:
                results.append(parsed)
    return results


def detect_bruteforce(log_entries: list[dict], threshold: int = 5, window_minutes: int = 5) -> list[dict]:
    """
    Detect brute-force SSH attacks by counting failed login attempts in syslog.
    """
    from collections import defaultdict

    failed_attempts = defaultdict(list)
    alerts = []

    for entry in log_entries:
        if entry.get("event_type") == "auth_failure":
            ip = entry.get("ip", "unknown")
            failed_attempts[ip].append(entry.get("timestamp", ""))

    for ip, timestamps in failed_attempts.items():
        if len(timestamps) >= threshold:
            alerts.append({
                "attack_type": "bruteforce_ssh",
                "source_ip": ip,
                "failed_attempts": len(timestamps),
                "cia_category": "Confidentiality",
                "severity": "High",
                "description": f"Detected {len(timestamps)} failed SSH attempts from {ip}"
            })

    return alerts
