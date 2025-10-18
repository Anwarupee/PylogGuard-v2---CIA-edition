# 🛡️ PyLogGuard v2 - CIA Edition

**Comprehensive Security Log Analysis & Visualization Platform**

A sophisticated log management system that ingests, analyzes, and visualizes security logs with CIA Triad classification (Confidentiality, Integrity, Availability). Built for security analysts, SOC teams, and cybersecurity professionals.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![MySQL](https://img.shields.io/badge/MySQL-8.0+-orange.svg)
![Grafana](https://img.shields.io/badge/Grafana-10.0+-orange.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

---

## 🌟 Features

### Core Capabilities
- 📊 **Multi-Source Log Ingestion**: Snort IDS, Squid Proxy, Syslog, Samba, Wireshark
- 🎯 **CIA Triad Classification**: Automatic categorization of security events
- 📈 **Advanced Visualization**: Grafana dashboards with Loki integration
- 🔍 **Attack Pattern Detection**: Automatic correlation of related security events
- 🗄️ **Scalable Storage**: MySQL database with optimized indexes

### Security Analysis
- ✅ Confidentiality threats (data breaches, unauthorized access)
- ✅ Integrity violations (file tampering, injection attacks)
- ✅ Availability attacks (DoS, DDoS, resource exhaustion)
- ✅ Severity-based prioritization (High, Medium, Low, Info)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Log Sources                              │
│  Snort IDS │ Squid Proxy │ Syslog │ Wireshark               │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│              PyLogGuard Ingestion Engine                     │
│  • Log Parsing  • CIA Classification  • Pattern Detection   │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│                    MySQL Database                            │
│  • log_entries  • alerts  • attack_patterns  • users        │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│                    Loki (Log Aggregation)                    │
│  • Stream-based storage  • Label indexing  • Fast queries   │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────────┐
│              Grafana Dashboards                              │
│  • Real-time monitoring  • CIA analytics  • Alerts          │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- MySQL 8.0+
- Docker & Docker Compose
- Git

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/PyLogGuardv2-CIA-edition.git
cd PyLogGuardv2-CIA-edition

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env with your database credentials

# 5. Initialize database
mysql -u root -p < core/schema.sql

# 6. Start Grafana & Loki
docker-compose up -d

# 7. Verify services
docker ps
```

---

## 📋 Usage

### Ingest Logs

```bash
# Ingest logs from directory
python ingest_logs.py -d demo/logs \
  --db-user root \
  --db-password yourpassword \
  --db-name attack_logs_db

# Update timestamps (for demo data)
mysql -u root -p attack_logs_db -e "UPDATE log_entries SET timestamp = NOW() - INTERVAL FLOOR(RAND() * 30) MINUTE;"
```

### Ship to Loki

```bash
# Ship all logs to Loki
python core/loki_shipper.py --use-env --mode all

# Ship only recent logs
python core/loki_shipper.py --use-env --mode incremental --hours 24
```

### Access Dashboards

```bash
# Open Grafana (default: http://localhost:3001)
# Username: yourpassword
# Password: yourpassword

# Navigate to Dashboards → PyLogGuard CIA Security Dashboard
```

---

## 🗂️ Project Structure

```
PyLogGuardv2-CIA-edition/
├── core/
│   ├── parsers/           # Log parsers for each source
│   │   ├── snort_parser.py
│   │   ├── proxy_parser.py
│   │   ├── syslog_parser.py
│   │   └── wireshark_parser.py
│   ├── loki_shipper.py    # Loki integration
│   ├── schema.sql         # Database schema
│   └── db_utils.py        # Database utilities
├── dashboard/
│   ├── loki/
│   │   └── loki-config.yaml
│   └── grafana/
│       └── dashboards/
├── demo/
│   └── logs/              # Sample log files
├── ingest_logs.py         # Main ingestion script
├── docker-compose.yml     # Docker services
└── README.md
```

---

## 🎯 Supported Log Sources

### 1. Snort IDS
- **Format**: Unified2, Fast Alert
- **Events**: Network intrusions, port scans, protocol anomalies
- **CIA Impact**: Primarily Availability and Confidentiality

### 2. Squid Proxy
- **Format**: Access logs (Common Log Format)
- **Events**: Web attacks, SQL injection, XSS, unauthorized access
- **CIA Impact**: All three categories

### 3. Syslog (SSH Auth)
- **Format**: Standard syslog format
- **Events**: Authentication failures, bruteforce attempts, successful logins
- **CIA Impact**: Confidentiality and Availability

### 4. Wireshark (PCAP)
- **Format**: Packet capture summaries
- **Events**: Network traffic analysis, attack patterns, protocol anomalies
- **CIA Impact**: All three categories

---

## 📊 CIA Triad Classification

### Confidentiality 🔒
- Unauthorized data access
- Authentication failures
- Data exfiltration attempts
- Privacy violations

### Integrity ✏️
- File tampering
- SQL injection
- XSS attacks
- Data modification

### Availability ⚡
- DoS/DDoS attacks
- Resource exhaustion
- Service disruptions
- Port scans

---

## 🔧 Configuration

### Database Configuration

Edit `.env`:
```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=yourpassword
DB_NAME=attack_logs_db
```

### Loki Configuration

Edit `dashboard/loki/loki-config.yaml`:
```yaml
limits_config:
  reject_old_samples: false
  reject_old_samples_max_age: 168h  # Accept 7-day old logs
  ingestion_rate_mb: 10
  ingestion_burst_size_mb: 20
```

### Grafana Data Source

1. Go to **Connections → Data Sources**
2. Add **Loki** data source
3. URL: `http://loki:3100`
4. Save & Test

---

## 📈 Dashboard Features

### Overview Panel
- Total log events gauge
- CIA Triad distribution pie chart
- Severity breakdown donut chart
- High-severity alerts counter

### Time Series Analysis
- Events over time by CIA category
- Source-based traffic analysis
- Severity trends with color coding

### Real-time Logs
- Live log stream filtered by severity
- Searchable and filterable
- Click-to-expand details

---

## 🚨 Alert Types

| Alert Type | Trigger Condition | Severity |
|------------|-------------------|----------|
| `bruteforce_detected` | 5+ auth failures from same IP | High |
| `proxy_high_severity_spike` | 5+ high-severity proxy events | High |
| `syslog_high_severity_spike` | 10+ high-severity syslog events | High |
| `dos_attack_detected` | 100+ packets in 10 seconds | Critical |

---

## 🧪 Testing

### Generate Test Data

```bash
# Generate realistic attack logs
python generate_test_logs.py

# Copy to demo directory
cp demo/logs_generated/* demo/logs/
```

### Run Attack Simulation

```bash
# From Kali Linux (attacker VM)
./attack_simulation.sh 192.168.56.10

# From Ubuntu (victim VM)
# Logs will be captured automatically
```

### Verify Ingestion

```bash
# Check database
mysql -u root -p attack_logs_db -e "
SELECT source, COUNT(*) as count 
FROM log_entries 
GROUP BY source;
"

# Check Loki
curl http://localhost:3100/loki/api/v1/labels
```

---

## 🐛 Troubleshooting

### No Data in Grafana

```bash
# 1. Check database has data
mysql -u root -p attack_logs_db -e "SELECT COUNT(*) FROM log_entries;"

# 2. Verify timestamps are recent
mysql -u root -p attack_logs_db -e "SELECT MIN(timestamp), MAX(timestamp) FROM log_entries;"

# 3. Update timestamps if needed
mysql -u root -p attack_logs_db -e "UPDATE log_entries SET timestamp = NOW() - INTERVAL FLOOR(RAND() * 30) MINUTE;"

# 4. Re-ship to Loki
python core/loki_shipper.py --use-env --mode all

# 5. Check Loki
curl http://localhost:3100/ready
```

### Loki Rejecting Old Logs

Error: `entry too far behind`

**Solution**: Edit `dashboard/loki/loki-config.yaml`
```yaml
limits_config:
  reject_old_samples: false
  reject_old_samples_max_age: 168h
```

Then restart:
```bash
docker-compose restart loki
```

### Parser Errors

```bash
# Check parser files exist
ls core/parsers/

# Test individual parser
python -c "from core.parsers.snort_parser import parse_snort; print(parse_snort('test.log'))"
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Snort**: Network intrusion detection
- **Grafana**: Visualization platform
- **Loki**: Log aggregation system
- **MySQL**: Database management
- **Python community**: Libraries and tools

---

## 📞 Contact

**Project Maintainer**: Muhammad Yanuar Andrianto Putra  
**Email**: muhammadyanuar141@gmail.com  
**GitHub**: [@Anwarupee](https://github.com/Anwarupee)  
**LinkedIn**: [Muhammad Yanuar Andrianto Putra](https://www.linkedin.com/in/muhammad-yanuar-andrianto-putra)

---

## 🗺️ Roadmap

- [ ] Machine learning-based anomaly detection
- [ ] Real-time alerting via Slack/Email
- [ ] Multi-tenant support
- [ ] API endpoints for external integrations
- [ ] Mobile dashboard app
- [ ] Advanced correlation rules engine

---

## 📚 Documentation

detailed documentation will soon be added

---

<div align="center">

**⭐ Star this repo if you find it useful! ⭐**

Made with ❤️ for the cybersecurity community

</div>
