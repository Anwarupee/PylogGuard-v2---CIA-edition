"""
Snort Parser
------------
Parses Snort IDS log lines into structured Python dictionaries.

Expected line example:
[**] [1:1000001:0] ICMP flood detected [**] [Priority: 2] {ICMP} 192.168.1.5 -> 192.168.1.10
"""

import re
from core.classifier import classify_log_entry

SNORT_REGEX = re.compile(
    r"\[\*\*\] \[(?P<sid>\d+:\d+:\d+)\] (?P<msg>.+?) \[\*\*\] \[Priority: (?P<priority>\d+)\] \{(?P<proto>\w+)\} (?P<src>[\d\.]+) -> (?P<dst>[\d\.]+)"
)

def parse_snort_line(line: str) -> dict | None:
    """Parse one line of Snort log."""
    match = SNORT_REGEX.search(line)
    if not match:
        return None

    data = match.groupdict()
    # Simplify event_type based on message content
    msg = data["msg"].lower()
    if "dos" in msg or "flood" in msg:
        data["event_type"] = "dos_attack"
    elif "unauthorized" in msg or "login" in msg:
        data["event_type"] = "unauthorized_access"
    else:
        data["event_type"] = "unknown"

    return classify_log_entry(data)

def parse_snort_file(path: str) -> list[dict]:
    """Parse all lines in a Snort log file."""
    results = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parsed = parse_snort_line(line)
            if parsed:
                results.append(parsed)
    return results