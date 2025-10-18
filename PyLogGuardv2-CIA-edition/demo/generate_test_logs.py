"""
Generate realistic attack logs for PyLogGuard testing
"""

import random
from datetime import datetime, timedelta
from pathlib import Path

# Create logs directory
LOG_DIR = Path("demo/logs_generated")
LOG_DIR.mkdir(exist_ok=True, parents=True)

# Attack IPs
ATTACKER_IPS = ["192.168.56.20", "10.0.0.50", "172.16.0.100"]
TARGET_IP = "192.168.56.10"

def generate_snort_logs(count=50):
    """Generate Snort IDS alerts"""
    signatures = [
        ("ET SCAN Potential SSH Scan", "2001219", "Availability"),
        ("ET EXPLOIT SQL Injection Attempt", "2010937", "Confidentiality"),
        ("ET WEB_SPECIFIC_APPS XSS Attempt", "2012647", "Integrity"),
        ("ET SCAN Nmap Scripting Engine", "2009582", "Availability"),
        ("ET POLICY Suspicious User-Agent", "2013028", "Confidentiality"),
    ]
    
    logs = []
    base_time = datetime.now() - timedelta(minutes=30)
    
    for i in range(count):
        sig_name, sid, cia = random.choice(signatures)
        src_ip = random.choice(ATTACKER_IPS)
        src_port = random.randint(40000, 65000)
        dst_port = random.choice([22, 80, 443, 3128])
        priority = random.choice([1, 2, 3])
        
        timestamp = base_time + timedelta(seconds=i*10)
        time_str = timestamp.strftime("%m/%d-%H:%M:%S.%f")[:-3]
        
        log = f"[**] [1:{sid}:{i}] {sig_name} [**]\n"
        log += f"[Priority: {priority}] \n"
        log += f"{time_str} {src_ip}:{src_port} -> {TARGET_IP}:{dst_port}\n"
        log += f"TCP TTL:64 TOS:0x0 ID:54321\n\n"
        
        logs.append(log)
    
    with open(LOG_DIR / "snort_alert.log", "w") as f:
        f.writelines(logs)
    
    print(f"✅ Generated {count} Snort alerts")

def generate_ssh_auth_logs(count=30):
    """Generate SSH authentication failure logs"""
    users = ["root", "admin", "testuser", "ubuntu", "kali"]
    
    logs = []
    base_time = datetime.now() - timedelta(minutes=25)
    
    for i in range(count):
        username = random.choice(users)
        src_ip = random.choice(ATTACKER_IPS)
        port = random.randint(40000, 65000)
        
        timestamp = base_time + timedelta(seconds=i*15)
        time_str = timestamp.strftime("%b %d %H:%M:%S")
        
        log = f"{time_str} ubuntu-server sshd[{random.randint(1000,9999)}]: "
        log += f"Failed password for {username} from {src_ip} port {port} ssh2\n"
        
        logs.append(log)
    
    # Add some successful logins
    for i in range(5):
        timestamp = base_time + timedelta(minutes=i*5)
        time_str = timestamp.strftime("%b %d %H:%M:%S")
        log = f"{time_str} ubuntu-server sshd[{random.randint(1000,9999)}]: "
        log += f"Accepted password for ubuntu from 192.168.56.1 port 50000 ssh2\n"
        logs.append(log)
    
    with open(LOG_DIR / "syslog_auth.log", "w") as f:
        f.writelines(logs)
    
    print(f"✅ Generated {count} SSH auth logs")

def generate_squid_logs(count=40):
    """Generate Squid proxy access logs"""
    methods = ["GET", "POST", "CONNECT"]
    domains = ["example.com", "malicious-site.com", "test-server.local"]
    attacks = [
        "/?id=1' OR '1'='1",  # SQL Injection
        "/search?q=<script>alert(1)</script>",  # XSS
        "/../../../etc/passwd",  # Path Traversal
        "/admin.php",  # Unauthorized access
    ]
    
    logs = []
    base_time = datetime.now() - timedelta(minutes=20)
    
    for i in range(count):
        timestamp = (base_time + timedelta(seconds=i*20)).timestamp()
        src_ip = random.choice(ATTACKER_IPS)
        method = random.choice(methods)
        domain = random.choice(domains)
        
        # Mix normal and attack requests
        if random.random() < 0.3:  # 30% attacks
            path = random.choice(attacks)
            status = random.choice([403, 500])
            size = random.randint(100, 500)
        else:  # Normal traffic
            path = f"/{random.choice(['index.html', 'about.php', 'images/logo.png'])}"
            status = 200
            size = random.randint(1000, 50000)
        
        log = f"{timestamp:.3f} {random.randint(10,100)} {src_ip} "
        log += f"TCP_MISS/{status} {size} {method} http://{domain}{path} "
        log += f"- HIER_DIRECT/{TARGET_IP} text/html\n"
        
        logs.append(log)
    
    with open(LOG_DIR / "squid_access.log", "w") as f:
        f.writelines(logs)
    
    print(f"✅ Generated {count} Squid proxy logs")

def generate_wireshark_summary(count=100):
    """Generate Wireshark packet summary"""
    protocols = ["TCP", "UDP", "ICMP", "HTTP"]
    
    logs = []
    base_time = datetime.now() - timedelta(minutes=30)
    
    logs.append("No.     Time           Source          Destination     Protocol Length Info\n")
    logs.append("-" * 90 + "\n")
    
    for i in range(1, count+1):
        time_offset = (i * 0.5)
        src_ip = random.choice(ATTACKER_IPS)
        proto = random.choice(protocols)
        length = random.randint(60, 1500)
        
        if proto == "TCP":
            info = f"{random.randint(40000,65000)} → {random.choice([22,80,443])} [SYN]"
        elif proto == "ICMP":
            info = "Echo (ping) request"
        elif proto == "HTTP":
            info = f"{random.choice(['GET', 'POST'])} / HTTP/1.1"
        else:
            info = f"UDP Port {random.randint(1000,9000)}"
        
        log = f"{i:6d}  {time_offset:8.6f}  {src_ip:15s} {TARGET_IP:15s} {proto:8s} {length:6d} {info}\n"
        logs.append(log)
    
    with open(LOG_DIR / "wireshark_summary.txt", "w") as f:
        f.writelines(logs)
    
    print(f"✅ Generated {count} Wireshark packets")

if __name__ == "__main__":
    print("🔧 Generating test attack logs...\n")
    
    generate_snort_logs(50)
    generate_ssh_auth_logs(30)
    generate_squid_logs(40)
    generate_wireshark_summary(100)
    
    print(f"\n✅ All logs generated in: {LOG_DIR.absolute()}")
    print("\n📋 Next steps:")
    print("   1. Copy logs to demo/logs/")
    print("   2. Run: python ingest_logs.py -d demo/logs ...")
    print("   3. Update timestamps and ship to Loki")