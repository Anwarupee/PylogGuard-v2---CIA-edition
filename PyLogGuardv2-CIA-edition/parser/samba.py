"""
Samba Parser
------------
Parses Samba/SMB file server logs into structured Python dictionaries.

Supports:
- Samba audit logs: [timestamp] smbd_audit: user|ip|status|action|resource
- Standard Samba logs: timestamp smbd[pid]: message

CIA Classification:
- Confidentiality: Unauthorized access, failed logins, sensitive file access
- Integrity: File modifications, deletions, permission changes
- Availability: Connection failures, service crashes
"""

import re
from datetime import datetime
from core.classifier import classify_log_entry

# Samba audit log format
# Example: [2025/10/08 10:30:45] smbd_audit: user|192.168.1.100|ok|connect|finance_share
AUDIT_REGEX = re.compile(
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r"smbd_audit:\s+"
    r"(?P<user>[^|]+)\|"
    r"(?P<client_ip>[^|]+)\|"
    r"(?P<status>[^|]+)\|"
    r"(?P<action>[^|]+)\|"
    r"(?P<resource>.+)"
)

# Standard Samba log format
# Example: 2025/10/08 10:30:45  smbd[12345]: user@192.168.1.100 logged in to share [finance]
STANDARD_REGEX = re.compile(
    r"(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"smbd\[(?P<pid>\d+)\]:\s+"
    r"(?P<message>.+)"
)

# Patterns for extracting info from standard log messages
LOGIN_PATTERN = re.compile(
    r"(?P<user>\S+)@(?P<client_ip>[\d\.]+)\s+logged in to share\s+\[(?P<share>[^\]]+)\]"
)

FAILED_LOGIN_PATTERN = re.compile(
    r"FAILED login for (?P<user>\S+) from (?P<client_ip>[\d\.]+)"
)

FILE_OPEN_PATTERN = re.compile(
    r"(?P<user>\S+)@(?P<client_ip>[\d\.]+)\s+opened file\s+(?P<filename>.+)"
)

# Sensitive share/file patterns
SENSITIVE_SHARES = [
    r"admin", r"finance", r"hr", r"payroll", r"confidential",
    r"executive", r"password", r"backup", r"database"
]

SENSITIVE_FILES = [
    r"\.xlsx$", r"\.docx$", r"\.pdf$", r"password", r"confidential",
    r"salary", r"budget", r"\.sql$", r"\.bak$", r"\.db$"
]

def parse_audit_line(line: str) -> dict | None:
    """Parse Samba audit log format."""
    match = AUDIT_REGEX.search(line)
    if not match:
        return None
    
    data = match.groupdict()
    
    # Standardize timestamp
    try:
        dt = datetime.strptime(data["timestamp"], "%Y/%m/%d %H:%M:%S")
        data["timestamp"] = dt.isoformat()
    except ValueError:
        pass
    
    # Classify the event
    data["event_type"] = classify_samba_event(
        action=data["action"],
        status=data["status"],
        resource=data["resource"],
        user=data["user"]
    )
    
    data["source"] = "samba"
    data["src"] = data["client_ip"]
    
    return classify_log_entry(data)

def parse_standard_line(line: str) -> dict | None:
    """Parse standard Samba log format."""
    match = STANDARD_REGEX.search(line)
    if not match:
        return None
    
    data = match.groupdict()
    message = data["message"]
    
    # Standardize timestamp
    try:
        dt = datetime.strptime(data["timestamp"], "%Y/%m/%d %H:%M:%S")
        data["timestamp"] = dt.isoformat()
    except ValueError:
        pass
    
    # Extract details from message
    login_match = LOGIN_PATTERN.search(message)
    if login_match:
        details = login_match.groupdict()
        data.update(details)
        data["action"] = "connect"
        data["status"] = "ok"
        data["resource"] = details["share"]
        data["src"] = details["client_ip"]
    
    failed_match = FAILED_LOGIN_PATTERN.search(message)
    if failed_match:
        details = failed_match.groupdict()
        data.update(details)
        data["action"] = "connect"
        data["status"] = "fail"
        data["resource"] = "unknown"
        data["src"] = details["client_ip"]
    
    file_match = FILE_OPEN_PATTERN.search(message)
    if file_match:
        details = file_match.groupdict()
        data.update(details)
        data["action"] = "open"
        data["status"] = "ok"
        data["resource"] = details["filename"]
        data["src"] = details["client_ip"]
    
    # Classify the event
    if "action" in data:
        data["event_type"] = classify_samba_event(
            action=data.get("action", "unknown"),
            status=data.get("status", "unknown"),
            resource=data.get("resource", "unknown"),
            user=data.get("user", "unknown")
        )
    else:
        data["event_type"] = "unknown"
    
    data["source"] = "samba"
    
    return classify_log_entry(data)

def classify_samba_event(action: str, status: str, resource: str, user: str) -> str:
    """
    Classify Samba events based on security indicators.
    
    Returns event_type string for CIA classification.
    """
    action_lower = action.lower()
    status_lower = status.lower()
    resource_lower = resource.lower()
    
    # Failed authentication attempts (Confidentiality - Bruteforce)
    if status_lower in ["fail", "failed", "denied"] and action_lower in ["connect", "login", "auth"]:
        return "auth_failure"
    
    # Check if accessing sensitive share (Confidentiality)
    if status_lower == "ok" and action_lower == "connect":
        for pattern in SENSITIVE_SHARES:
            if re.search(pattern, resource_lower):
                return "sensitive_share_access"
    
    # Check if accessing sensitive file (Confidentiality)
    if status_lower == "ok" and action_lower in ["open", "read"]:
        for pattern in SENSITIVE_FILES:
            if re.search(pattern, resource_lower):
                return "sensitive_file_access"
    
    # File modifications (Integrity)
    if action_lower in ["unlink", "rmdir", "rename"]:
        return "file_deletion"
    
    if action_lower in ["write", "pwrite", "mkdir"]:
        return "file_modification"
    
    if action_lower in ["chmod", "chown"]:
        return "permission_change"
    
    # Mass file access pattern (potential data exfiltration)
    # This would need to be detected by analyzing multiple logs together
    # For now, we'll mark as normal if opened many files
    
    # Connection issues (Availability)
    if status_lower in ["timeout", "refused", "error"]:
        return "connection_failure"
    
    # Normal successful operations
    if status_lower == "ok":
        if action_lower == "connect":
            return "share_access"
        elif action_lower in ["open", "read"]:
            return "file_access"
        elif action_lower == "close":
            return "file_close"
    
    return "unknown"

def parse_samba_line(line: str) -> dict | None:
    """
    Auto-detect and parse Samba log line (audit or standard format).
    """
    # Try audit format first
    result = parse_audit_line(line)
    if result:
        return result
    
    # Fall back to standard format
    result = parse_standard_line(line)
    if result:
        return result
    
    return None

def parse_samba_file(path: str) -> list[dict]:
    """Parse all lines in a Samba log file."""
    results = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parsed = parse_samba_line(line)
            if parsed:
                results.append(parsed)
    return results

def detect_bruteforce(log_entries: list[dict], threshold: int = 5, window_minutes: int = 5) -> list[dict]:
    """
    Detect bruteforce attacks by counting failed login attempts.
    
    Args:
        log_entries: List of parsed Samba logs
        threshold: Number of failed attempts to trigger alert
        window_minutes: Time window to check (in minutes)
        
    Returns:
        List of potential bruteforce attack records
    """
    from collections import defaultdict
    from datetime import timedelta
    
    failed_attempts = defaultdict(list)
    alerts = []
    
    for entry in log_entries:
        if entry.get("event_type") == "auth_failure":
            ip = entry.get("src", "unknown")
            timestamp = entry.get("timestamp", "")
            failed_attempts[ip].append(timestamp)
    
    # Check each IP for bruteforce pattern
    for ip, timestamps in failed_attempts.items():
        if len(timestamps) >= threshold:
            alerts.append({
                "attack_type": "bruteforce_samba",
                "source_ip": ip,
                "failed_attempts": len(timestamps),
                "cia_category": "Confidentiality",
                "severity": "High",
                "description": f"Detected {len(timestamps)} failed login attempts from {ip}"
            })
    
    return alerts