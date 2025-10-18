"""
Wireshark Parser
----------------
Parses textual Wireshark / tshark exports into structured Python dictionaries.

Notes:
- Designed for simple text exports (e.g., `tshark -r file.pcap -T ek` or -V dumps)
  but uses heuristics to detect:
    * HTTP plaintext credentials (Confidentiality)
    * Telnet plaintext exchanges (Confidentiality)
    * SSH traffic (encrypted -> treated as secure_channel)
    * DNS tunneling suspicion (long/encoded labels / many subdomains)
    * Large payloads (possible data exfiltration -> Confidentiality)
    * ICMP floods / high packet size (Availability)
- For production, prefer parsing pcap with pyshark or scapy; this is a light-weight text parser.
"""

import re
from datetime import datetime
from core.classifier import classify_log_entry

# Basic regexes (tuned for plain textual tshark-like lines)
# Example textual lines that may be produced by `tshark -V` or `tshark -T fields -e frame.time -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info`
# "2025-10-08 10:30:45.123456  192.168.1.10 -> 192.168.1.20  HTTP  GET /login.php"
WIRESHARK_LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}[-/]\d{2}[-/]\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<src>[\d\.]+)(?:\s*->\s*)(?P<dst>[\d\.]+)\s+"
    r"(?P<proto>\S+)\s+(?P<info>.+)$"
)

# Heuristics
HTTP_AUTH_HDR = re.compile(r"(Authorization:\s*Basic|user=|username=|password=|passwd=|login=)", re.IGNORECASE)
HTTP_POST_PASS = re.compile(r"(POST|PUT).*password=|passwd=|login=", re.IGNORECASE)
TELNET_KEYWORDS = re.compile(r"\b(login|password|username|pass)\b", re.IGNORECASE)
DNS_LABEL_B64 = re.compile(r"[A-Za-z0-9+/=]{20,}")  # long base64-like label
DNS_MANY_SUBDOMAINS = re.compile(r"([a-z0-9-]+\.){5,}", re.IGNORECASE)  # many subdomains
LARGE_PAYLOAD_BYTES = 100000  # threshold for potential exfil in bytes (heuristic)

def parse_wireshark_line(line: str) -> dict | None:
    """Parse a single exported Wireshark line into structured dict."""
    line = line.strip()
    if not line:
        return None

    m = WIRESHARK_LINE_RE.match(line)
    if not m:
        # try a simpler heuristic: lines that include HTTP/SSH/TELNET keywords
        lower = line.lower()
        if "telnet" in lower or "ssh" in lower or "http" in lower or "dns" in lower:
            # create a minimal struct
            return classify_log_entry({
                "timestamp": None,
                "src": None,
                "dst": None,
                "proto": None,
                "info": line,
                "event_type": heuristically_classify_by_text(line),
                "source": "wireshark"
            })
        return None

    data = m.groupdict()
    # Normalize timestamp to ISO if possible
    try:
        dt = datetime.fromisoformat(data["timestamp"])
        data["timestamp"] = dt.isoformat()
    except Exception:
        pass

    proto = data.get("proto", "").upper()
    info = data.get("info", "")

    # Heuristics to set event_type
    event_type = heuristically_classify_by_fields(proto, info, data)

    structured = {
        "timestamp": data.get("timestamp"),
        "src": data.get("src"),
        "dst": data.get("dst"),
        "proto": proto,
        "info": info,
        "event_type": event_type,
        "source": "wireshark"
    }

    return classify_log_entry(structured)

def heuristically_classify_by_fields(proto: str, info: str, data: dict) -> str:
    """Use protocol + info heuristics to determine event_type."""
    info_lower = (info or "").lower()

    # HTTP
    if proto in ("HTTP",) or "http" in info_lower:
        # Check for credentials leaked in URL or headers
        if HTTP_AUTH_HDR.search(info) or HTTP_POST_PASS.search(info):
            return "http_plaintext_credentials"
        # large upload attempt heuristic
        m_bytes = re.search(r"bytes=(\d+)", info_lower)
        if m_bytes and int(m_bytes.group(1)) > LARGE_PAYLOAD_BYTES:
            return "http_large_upload"
        # normal HTTP traffic
        return "http_unencrypted"

    # HTTPS (port 443 or TLS)
    if proto in ("TLS", "SSL", "HTTPS") or ":443" in info_lower or "https" in info_lower:
        return "https_encrypted"

    # Telnet detection: often proto column may say TELNET or info contains telnet commands
    if proto == "TELNET" or "telnet" in info_lower:
        # Check for login/password keywords in info -> plaintext creds
        if TELNET_KEYWORDS.search(info):
            return "telnet_plaintext"
        return "telnet_activity"

    # SSH
    if proto == "SSH" or "ssh" in info_lower:
        # SSH payloads are encrypted; treat as secure unless known exploit strings present
        return "ssh_encrypted"

    # DNS
    if proto == "DNS" or "dns" in info_lower:
        # heuristics: long label or many subdomains -> possible DNS tunneling
        if DNS_LABEL_B64.search(info) or DNS_MANY_SUBDOMAINS.search(info):
            return "dns_tunneling_suspected"
        return "dns_query"

    # ICMP / potential DoS indicators
    if proto == "ICMP" or "icmp" in info_lower:
        # big ICMP floods may show counts or 'Echo (ping) request'
        if "echo" in info_lower or "flood" in info_lower:
            return "icmp_suspected_dos"
        return "icmp"

    # Generic TCP or large payloads
    m_sz = re.search(r"length\s+(\d+)|(\d+)\s+bytes", info_lower)
    if m_sz:
        try:
            sz = int(m_sz.group(1) or m_sz.group(2))
            if sz > LARGE_PAYLOAD_BYTES:
                return "large_payload"
        except Exception:
            pass

    # fallback to text-based heuristics
    return heuristically_classify_by_text(info)

def heuristically_classify_by_text(text: str) -> str:
    """Fallback textual heuristics."""
    t = (text or "").lower()
    if "login:" in t and "password" in t:
        return "telnet_plaintext"
    if "failed password" in t or "authentication failure" in t:
        return "auth_failure"
    if "http" in t and "get" in t and "password" in t:
        return "http_plaintext_credentials"
    if "dns" in t and ("txt" in t or "long domain" in t):
        return "dns_tunneling_suspected"
    if "syn flood" in t or "dos" in t or "flood" in t:
        return "dos_related"
    return "unknown"

def parse_wireshark_file(path: str) -> list[dict]:
    """Parse all lines in a textual Wireshark/tshark export file."""
    results = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parsed = parse_wireshark_line(line)
            if parsed:
                results.append(parsed)
    return results
