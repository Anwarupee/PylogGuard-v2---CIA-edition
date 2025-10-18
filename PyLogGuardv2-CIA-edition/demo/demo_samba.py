"""
Test & Demo Script for Samba Parser
------------------------------------
Generates sample Samba logs and tests the parser.
"""

import sys
import os

# Sample Samba audit logs
AUDIT_TEST_LOGS = """
[2025/10/08 10:30:45] smbd_audit: john|192.168.1.100|ok|connect|public_docs
[2025/10/08 10:30:46] smbd_audit: attacker|192.168.1.101|fail|connect|admin_share
[2025/10/08 10:30:47] smbd_audit: attacker|192.168.1.101|fail|connect|admin_share
[2025/10/08 10:30:48] smbd_audit: attacker|192.168.1.101|fail|connect|admin_share
[2025/10/08 10:30:49] smbd_audit: attacker|192.168.1.101|fail|connect|admin_share
[2025/10/08 10:30:50] smbd_audit: attacker|192.168.1.101|fail|connect|admin_share
[2025/10/08 10:30:51] smbd_audit: cfo|192.168.1.102|ok|open|Q4_financial_report.xlsx
[2025/10/08 10:30:52] smbd_audit: hr_manager|192.168.1.103|ok|connect|hr_confidential
[2025/10/08 10:30:53] smbd_audit: backup_user|192.168.1.104|ok|open|database_backup.sql
[2025/10/08 10:30:54] smbd_audit: malicious|192.168.1.105|ok|unlink|important_file.docx
[2025/10/08 10:30:55] smbd_audit: admin|192.168.1.106|ok|write|config.ini
[2025/10/08 10:30:56] smbd_audit: user|192.168.1.107|timeout|connect|remote_share
"""

# Sample standard Samba logs
STANDARD_TEST_LOGS = """
2025/10/08 10:30:45  smbd[12345]: john@192.168.1.100 logged in to share [public]
2025/10/08 10:30:46  smbd[12346]: FAILED login for attacker from 192.168.1.101
2025/10/08 10:30:47  smbd[12347]: FAILED login for attacker from 192.168.1.101
2025/10/08 10:30:48  smbd[12348]: FAILED login for attacker from 192.168.1.101
2025/10/08 10:30:49  smbd[12349]: FAILED login for attacker from 192.168.1.101
2025/10/08 10:30:50  smbd[12350]: cfo@192.168.1.102 opened file salary_data.xlsx
2025/10/08 10:30:51  smbd[12351]: admin@192.168.1.103 logged in to share [finance]
2025/10/08 10:30:52  smbd[12352]: backup@192.168.1.104 opened file company_db.bak
"""

def generate_test_files():
    """Generate test Samba log files."""
    os.makedirs("demo/logs", exist_ok=True)
    
    with open("demo/logs/samba_audit.log", "w") as f:
        f.write(AUDIT_TEST_LOGS)
    
    with open("demo/logs/samba_standard.log", "w") as f:
        f.write(STANDARD_TEST_LOGS)
    
    print("✅ Test log files generated:")
    print("   - demo/logs/samba_audit.log")
    print("   - demo/logs/samba_standard.log")

def test_parser():
    """Test the Samba parser with generated logs."""
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from parser.samba import parse_samba_file, detect_bruteforce
    
    print("\n" + "="*70)
    print("Testing Samba Audit Format Parser")
    print("="*70)
    
    results = parse_samba_file("demo/logs/samba_audit.log")
    for i, entry in enumerate(results, 1):
        print(f"\n[Entry {i}]")
        print(f"  Timestamp: {entry.get('timestamp')}")
        print(f"  User: {entry.get('user')}")
        print(f"  Source IP: {entry.get('src')}")
        print(f"  Action: {entry.get('action')}")
        print(f"  Resource: {entry.get('resource')}")
        print(f"  Status: {entry.get('status')}")
        print(f"  Event Type: {entry.get('event_type')}")
        print(f"  CIA Category: {entry.get('cia_category')}")
        print(f"  Severity: {entry.get('severity')}")
    
    print("\n" + "="*70)
    print("Testing Samba Standard Format Parser")
    print("="*70)
    
    results2 = parse_samba_file("demo/logs/samba_standard.log")
    for i, entry in enumerate(results2, 1):
        print(f"\n[Entry {i}]")
        print(f"  Timestamp: {entry.get('timestamp')}")
        print(f"  User: {entry.get('user')}")
        print(f"  Source IP: {entry.get('src')}")
        print(f"  Action: {entry.get('action')}")
        print(f"  Resource: {entry.get('resource')}")
        print(f"  Event Type: {entry.get('event_type')}")
        print(f"  CIA Category: {entry.get('cia_category')}")
    
    print("\n" + "="*70)
    print("Bruteforce Detection Analysis")
    print("="*70)
    
    all_results = results + results2
    bruteforce_alerts = detect_bruteforce(all_results, threshold=3)
    
    if bruteforce_alerts:
        for alert in bruteforce_alerts:
            print(f"\n🚨 ALERT: {alert['attack_type']}")
            print(f"  Source IP: {alert['source_ip']}")
            print(f"  Failed Attempts: {alert['failed_attempts']}")
            print(f"  CIA Impact: {alert['cia_category']}")
            print(f"  Severity: {alert['severity']}")
            print(f"  Description: {alert['description']}")
    else:
        print("\n✅ No bruteforce attacks detected.")
    
    print("\n" + "="*70)
    print("CIA Distribution Summary")
    print("="*70)
    
    cia_counts = {"Confidentiality": 0, "Integrity": 0, "Availability": 0}
    event_types = {}
    
    for entry in all_results:
        cia = entry.get("cia_category", "Unknown")
        if cia in cia_counts:
            cia_counts[cia] += 1
        
        event_type = entry.get("event_type", "unknown")
        event_types[event_type] = event_types.get(event_type, 0) + 1
    
    total = sum(cia_counts.values())
    for category, count in cia_counts.items():
        percentage = (count / total * 100) if total > 0 else 0
        print(f"  {category.upper()}: {count} ({percentage:.1f}%)")
    
    print("\n" + "="*70)
    print("Event Types Detected")
    print("="*70)
    for event_type, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True):
        print(f"  {event_type}: {count}")

if __name__ == "__main__":
    print("🔧 Samba Parser Test Suite")
    print("="*70)
    
    generate_test_files()
    
    try:
        test_parser()
        print("\n✅ All tests completed successfully!")
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()