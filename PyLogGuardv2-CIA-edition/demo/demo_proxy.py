"""
Test & Demo Script for Proxy Parser
------------------------------------
Generates sample proxy logs and tests the parser.
Use this to verify your proxy_parser.py works correctly.
"""

import sys
import os

# Sample test logs covering different CIA scenarios
SQUID_TEST_LOGS = """
1728388245.123 245 192.168.1.100 TCP_MISS/200 1234 GET http://example.com/index.html
1728388246.456 156 192.168.1.101 TCP_MISS/401 512 GET http://internal.company.com/admin/users.php
1728388247.789 12034 192.168.1.102 TCP_MISS/200 8945632 POST http://external.site/upload.php
1728388248.012 89 192.168.1.103 TCP_MISS/403 256 GET http://intranet.local/config/database.xml
1728388249.345 523 192.168.1.104 TCP_MISS/200 2048 GET http://malicious.com/login.php?password=admin123
1728388250.678 45 192.168.1.105 TCP_MISS/503 128 GET http://service.company.com/api/data
1728388251.901 8923 192.168.1.106 TCP_MISS/200 4567890 PUT http://cloud.storage.com/backup/.env
1728388252.234 167 192.168.1.107 TCP_MISS/200 3456 GET http://example.com/search?q=<script>alert(1)</script>
"""

APACHE_TEST_LOGS = """
192.168.1.100 - - [08/Oct/2025:10:30:45 +0000] "GET /index.html HTTP/1.1" 200 5432
192.168.1.101 - - [08/Oct/2025:10:30:46 +0000] "GET /admin/config.php HTTP/1.1" 401 256
192.168.1.102 - - [08/Oct/2025:10:30:47 +0000] "POST /api/upload HTTP/1.1" 200 8945632
192.168.1.103 - - [08/Oct/2025:10:30:48 +0000] "GET /credentials/passwords.txt HTTP/1.1" 403 128
192.168.1.104 - - [08/Oct/2025:10:30:49 +0000] "GET /login?token=secret123 HTTP/1.1" 200 1024
192.168.1.105 - - [08/Oct/2025:10:30:50 +0000] "GET /api/data HTTP/1.1" 500 512
192.168.1.106 - - [08/Oct/2025:10:30:51 +0000] "GET /../../../etc/passwd HTTP/1.1" 200 2048
"""

def generate_test_files():
    """Generate test log files."""
    os.makedirs("demo/logs", exist_ok=True)
    
    with open("demo/logs/proxy_squid.log", "w") as f:
        f.write(SQUID_TEST_LOGS)
    
    with open("demo/logs/proxy_apache.log", "w") as f:
        f.write(APACHE_TEST_LOGS)
    
    print("✅ Test log files generated:")
    print("   - demo/logs/proxy_squid.log")
    print("   - demo/logs/proxy_apache.log")

def test_parser():
    """Test the proxy parser with generated logs."""
    # Import your parser
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from parser.proxy import parse_proxy_file
    
    print("\n" + "="*70)
    print("Testing Squid Format Parser")
    print("="*70)
    
    results = parse_proxy_file("demo/logs/proxy_squid.log")
    for i, entry in enumerate(results, 1):
        print(f"\n[Entry {i}]")
        print(f"  Timestamp: {entry.get('timestamp')}")
        print(f"  Source IP: {entry.get('src')}")
        print(f"  URL: {entry.get('url')}")
        print(f"  Event Type: {entry.get('event_type')}")
        print(f"  CIA Category: {entry.get('cia_category')}")
        print(f"  Status: {entry.get('status')}")
    
    print("\n" + "="*70)
    print("Testing Apache Format Parser")
    print("="*70)
    
    results = parse_proxy_file("demo/logs/proxy_apache.log")
    for i, entry in enumerate(results, 1):
        print(f"\n[Entry {i}]")
        print(f"  Timestamp: {entry.get('timestamp')}")
        print(f"  Source IP: {entry.get('src')}")
        print(f"  URL: {entry.get('url')}")
        print(f"  Event Type: {entry.get('event_type')}")
        print(f"  CIA Category: {entry.get('cia_category')}")
        print(f"  Status: {entry.get('status')}")
    
    print("\n" + "="*70)
    print("CIA Distribution Summary")
    print("="*70)
    
    all_results = parse_proxy_file("demo/logs/proxy_squid.log") + \
                  parse_proxy_file("demo/logs/proxy_apache.log")
    
    cia_counts = {"confidentiality": 0, "integrity": 0, "availability": 0}
    for entry in all_results:
        cia = entry.get("cia_category", "unknown")
        if cia in cia_counts:
            cia_counts[cia] += 1
    
    total = sum(cia_counts.values())
    for category, count in cia_counts.items():
        percentage = (count / total * 100) if total > 0 else 0
        print(f"  {category.upper()}: {count} ({percentage:.1f}%)")

if __name__ == "__main__":
    print("🔧 Proxy Parser Test Suite")
    print("="*70)
    
    # Generate test files
    generate_test_files()
    
    # Test parser
    try:
        test_parser()
        print("\n✅ All tests completed successfully!")
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()