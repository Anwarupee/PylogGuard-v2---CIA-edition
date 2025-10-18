"""
Proxy Parser
------------
Parses proxy server logs (Squid & Apache formats) into structured Python dictionaries.

Supports:
- Squid format: timestamp response_time client_ip status bytes method url
- Apache format: client_ip - - [timestamp] "method url protocol" status bytes

CIA Classification:
- Confidentiality: Suspicious URLs, auth failures, data exfiltration
- Integrity: POST/PUT to sensitive endpoints, unusual parameters
- Availability: 5xx errors, timeouts, high response times
"""

import re
from datetime import datetime
from core.classifier import classify_log_entry

# Squid format regex
# Example: 1728388245.123 245 192.168.1.100 TCP_MISS/200 1234 GET http://example.com/login.php
SQUID_REGEX = re.compile(
    r"(?P<timestamp>[\d\.]+)\s+"
    r"(?P<response_time>\d+)\s+"
    r"(?P<client_ip>[\d\.]+)\s+"
    r"(?P<result_code>\S+)/(?P<status>\d+)\s+"
    r"(?P<bytes>\d+)\s+"
    r"(?P<method>\w+)\s+"
    r"(?P<url>\S+)"
)

# Apache Combined format regex
# Example: 192.168.1.100 - - [08/Oct/2025:10:30:45 +0000] "GET /admin/config.php HTTP/1.1" 200 5432
APACHE_REGEX = re.compile(
    r"(?P<client_ip>[\d\.]+)\s+-\s+-\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<method>\w+)\s+(?P<url>\S+)\s+(?P<protocol>HTTP/[\d\.]+)"\s+'
    r"(?P<status>\d+)\s+"
    r"(?P<bytes>\d+|-)"
)

# Suspicious patterns for CIA classification
SENSITIVE_PATHS = [
    r"/admin", r"/config", r"/api/keys", r"/credentials", 
    r"/passwords", r"/users", r"\.env", r"/backup", r"/database"
]

SUSPICIOUS_PARAMS = [
    r"password=", r"api_key=", r"token=", r"secret=",
    r"<script", r"javascript:", r"union\s+select", r"\.\./"
]

def parse_squid_line(line: str) -> dict | None:
    """Parse one line of Squid proxy log."""
    match = SQUID_REGEX.search(line)
    if not match:
        return None
    
    data = match.groupdict()
    
    # Convert Unix timestamp to readable format
    try:
        ts = float(data["timestamp"])
        data["timestamp"] = datetime.fromtimestamp(ts).isoformat()
    except (ValueError, OSError):
        data["timestamp"] = data["timestamp"]
    
    # Classify event type based on URL and status
    data["event_type"] = classify_proxy_event(
        url=data["url"],
        method=data["method"],
        status=int(data["status"]),
        response_time=int(data["response_time"])
    )
    
    data["source"] = "proxy"
    data["src"] = data["client_ip"]
    return classify_log_entry(data)

def parse_apache_line(line: str) -> dict | None:
    """Parse one line of Apache proxy log."""
    match = APACHE_REGEX.search(line)
    if not match:
        return None
    
    data = match.groupdict()
    
    # Apache timestamp is already formatted: [08/Oct/2025:10:30:45 +0000]
    # Convert to ISO format
    try:
        dt = datetime.strptime(data["timestamp"], "%d/%b/%Y:%H:%M:%S %z")
        data["timestamp"] = dt.isoformat()
    except ValueError:
        pass
    
    # Handle missing bytes
    if data["bytes"] == "-":
        data["bytes"] = "0"
    
    # Classify event type
    data["event_type"] = classify_proxy_event(
        url=data["url"],
        method=data["method"],
        status=int(data["status"]),
        response_time=0  # Apache logs don't include response time
    )
    
    data["source"] = "proxy"
    data["src"] = data["client_ip"]
    return classify_log_entry(data)

def classify_proxy_event(url: str, method: str, status: int, response_time: int) -> str:
    """
    Classify proxy events based on security indicators.
    
    Returns event_type string for CIA classification.
    """
    url_lower = url.lower()
    
    # Check for sensitive path access (Confidentiality)
    for pattern in SENSITIVE_PATHS:
        if re.search(pattern, url_lower):
            if status == 200:
                return "unauthorized_access"  # Successful access to sensitive area
            elif status in [401, 403]:
                return "access_denied"  # Attempted unauthorized access
    
    # Check for suspicious parameters (Integrity)
    for pattern in SUSPICIOUS_PARAMS:
        if re.search(pattern, url_lower):
            return "suspicious_request"  # Potential injection or credential leak
    
    # Check for data exfiltration (Confidentiality)
    if method in ["POST", "PUT"] and int(response_time) > 5000:
        return "data_exfiltration"  # Large upload detected
    
    # Authentication failures (Confidentiality)
    if status == 401:
        return "auth_failure"
    
    if status == 403:
        return "access_forbidden"
    
    # Server errors (Availability)
    if 500 <= status < 600:
        return "service_unavailable"
    
    # Connection issues (Availability)
    if status in [408, 504, 0]:
        return "connection_timeout"
    
    # Normal activity
    if 200 <= status < 300:
        return "normal_access"
    
    # Catch-all
    return "unknown"

def parse_proxy_line(line: str) -> dict | None:
    """
    Auto-detect and parse proxy log line (Squid or Apache format).
    """
    # Try Squid format first (more structured)
    result = parse_squid_line(line)
    if result:
        return result
    
    # Fall back to Apache format
    result = parse_apache_line(line)
    if result:
        return result
    
    return None

def parse_proxy_file(path: str) -> list[dict]:
    """Parse all lines in a proxy log file."""
    results = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parsed = parse_proxy_line(line)
            if parsed:
                results.append(parsed)
    return results