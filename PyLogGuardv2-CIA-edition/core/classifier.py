
"""
CIA Classifier Module
---------------------
Classifies log events into Confidentiality, Integrity, or Availability impact.

CIA Triad:
- Confidentiality: Unauthorized access to data, credential theft, data leaks
- Integrity: Data modification, tampering, injection attacks
- Availability: Service disruption, DoS, resource exhaustion
"""

CIA_RULES = {
    # Network & Intrusion Events (from Snort)
    "unauthorized_access": "Confidentiality",
    "dos_attack": "Availability",
    "bruteforce": "Confidentiality",
    "port_scan": "Confidentiality",
    "malware": "Integrity",
    "exploit_attempt": "Integrity",
    
    # Proxy Events (Web Traffic)
    "auth_failure": "Confidentiality",
    "access_denied": "Confidentiality",
    "access_forbidden": "Confidentiality",
    "data_exfiltration": "Confidentiality",
    "suspicious_request": "Integrity",
    "service_unavailable": "Availability",
    "connection_timeout": "Availability",
    "normal_access": "None",  # Not a threat
    
    # File Access Events (Samba)
    "file_unauthorized_access": "Confidentiality",
    "file_modification": "Integrity",
    "file_deletion": "Integrity",
    "share_access_denied": "Confidentiality",
    "sensitive_share_access": "Confidentiality",
    "sensitive_file_access": "Confidentiality",
    "permission_change": "Integrity",
    "connection_failure": "Availability",
    "share_access": "None",
    "file_access": "None",
    "file_close": "None",
    
    # System Events (Syslog) 
    "privilege_escalation": "Integrity",
    "sudo_abuse": "Integrity",
    "unauthorized_login": "Confidentiality",
    "user_addition": "Integrity",
    "system_modification": "Integrity",
    "config_change": "Integrity",
    "kernel_panic": "Availability",
    "service_crash": "Availability",
    "service_restart": "Availability",
    "system_shutdown": "Availability",
    "data_modification": "Integrity",
    "service_disruption": "Availability",
    
    # Network Protocol Events (Wireshark) - to be added
    "http_plaintext_credentials": "Confidentiality",
    "http_large_upload": "Confidentiality",
    "http_unencrypted": "Confidentiality",
    "https_encrypted": "None",
    "telnet_plaintext": "Confidentiality",
    "telnet_activity": "None",
    "ssh_encrypted": "None",
    "dns_tunneling_suspected": "Confidentiality",
    "dns_query": "None",
    "icmp_suspected_dos": "Availability",
    "icmp": "None",
    "large_payload": "Confidentiality",
    "dos_related": "Availability",
    "mitm_attack": "Confidentiality",
    "protocol_violation": "Integrity",
    "bandwidth_exhaustion": "Availability",
    "unknown": "Unknown",
}

def classify_event(event_type: str) -> str:
    """
    Classify event type into CIA category.
    
    Args:
        event_type: String identifying the type of security event
        
    Returns:
        CIA category: "Confidentiality", "Integrity", "Availability", "None", or "Unknown"
    """
    return CIA_RULES.get(event_type.lower(), "Unknown")

def classify_log_entry(log_entry: dict) -> dict:
    """
    Takes structured log (from parser) and attaches CIA category.
    
    Args:
        log_entry: Dictionary containing parsed log data with 'event_type' key
        
    Returns:
        Same dictionary with added 'cia_category' key
    """
    event_type = log_entry.get("event_type", "unknown")
    cia_category = classify_event(event_type)
    log_entry["cia_category"] = cia_category
    
    # Add severity level based on CIA category
    severity_map = {
        "Confidentiality": "High",
        "Integrity": "High", 
        "Availability": "Medium",
        "Unknown": "Low",
        "None": "Info"
    }
    log_entry["severity"] = severity_map.get(cia_category, "Low")
    
    return log_entry

def get_cia_statistics(log_entries: list[dict]) -> dict:
    """
    Calculate CIA distribution statistics from a list of log entries.
    
    Args:
        log_entries: List of parsed and classified log entries
        
    Returns:
        Dictionary with counts and percentages for each CIA category
    """
    stats = {
        "Confidentiality": 0,
        "Integrity": 0,
        "Availability": 0,
        "Unknown": 0,
        "None": 0
    }
    
    for entry in log_entries:
        cia = entry.get("cia_category", "Unknown")
        if cia in stats:
            stats[cia] += 1
    
    total = sum(stats.values())
    
    # Add percentages
    result = {}
    for category, count in stats.items():
        percentage = (count / total * 100) if total > 0 else 0
        result[category] = {
            "count": count,
            "percentage": round(percentage, 2)
        }
    
    result["total"] = total