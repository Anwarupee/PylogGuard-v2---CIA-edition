# Phase 3: Database Setup Guide

## 📋 Prerequisites

- MySQL 8.0+ installed
- Python 3.10+
- `mysql-connector-python` package

## 🚀 Step-by-Step Setup

### Step 1: Install MySQL (if not installed)

**Windows:**
```bash
# Download from: https://dev.mysql.com/downloads/mysql/
# Or use Chocolatey:
choco install mysql
```

**Linux:**
```bash
sudo apt update
sudo apt install mysql-server
sudo systemctl start mysql
```

### Step 2: Create Database and User

Login to MySQL:
```bash
mysql -u root -p
```

Run these commands:
```sql
-- Create database
CREATE DATABASE pylogguard_v2 CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create user (CHANGE PASSWORD!)
CREATE USER 'pylogguard'@'localhost' IDENTIFIED BY 'your_strong_password_here';

-- Grant permissions
GRANT ALL PRIVILEGES ON pylogguard_v2.* TO 'pylogguard'@'localhost';
FLUSH PRIVILEGES;

-- Verify
SHOW DATABASES;
SELECT user, host FROM mysql.user WHERE user='pylogguard';

-- Exit
EXIT;
```

### Step 3: Import Schema

```bash
# Navigate to your project directory
cd PyLogGuardv2-CIA-edition

# Import the schema
mysql -u pylogguard -p pylogguard_v2 < schema_cia_enhanced.sql

# Verify tables were created
mysql -u pylogguard -p pylogguard_v2 -e "SHOW TABLES;"
```

Expected output:
```
+---------------------------+
| Tables_in_pylogguard_v2   |
+---------------------------+
| alerts                    |
| attack_patterns           |
| audit_log                 |
| daily_statistics          |
| log_entries               |
| roles                     |
| users                     |
+---------------------------+
```

### Step 4: Install Python Dependencies

```bash
pip install mysql-connector-python
```

### Step 5: Configure Database Connection

Create `.env` file in project root:
```bash
# .env file
DB_HOST=localhost
DB_USER=pylogguard
DB_PASSWORD=your_strong_password_here
DB_NAME=pylogguard_v2
DB_POOL_SIZE=5
```

**IMPORTANT:** Add `.env` to `.gitignore`:
```bash
echo ".env" >> .gitignore
```

### Step 6: Update database_manager.py Configuration

Option A: Use environment variables (recommended):
```python
from core.database_manager import create_db_config_from_env, DatabaseManager

config = create_db_config_from_env()
db = DatabaseManager(config)
```

Option B: Direct configuration:
```python
config = {
    'host': 'localhost',
    'user': 'pylogguard',
    'password': 'your_password',
    'database': 'pylogguard_v2',
    'pool_size': 5
}
db = DatabaseManager(config)
```

### Step 7: Test Connection

```bash
python test_database_integration.py
```

Expected output:
```
✅ Database connection successful!
   Total logs: 0
   Unresolved incidents: 0

🎉 Database manager is ready to use!
```

## 🧪 Testing

### Test 1: Basic Operations
```bash
python test_database_integration.py
```

This will:
- Test database connection
- Insert test logs
- Parse and import demo logs
- Run CIA statistics queries
- Test search functionality
- Test alert system

### Test 2: Manual Verification

```bash
mysql -u pylogguard -p pylogguard_v2
```

```sql
-- Check log entries
SELECT COUNT(*) as total_logs FROM log_entries;

-- Check CIA distribution
SELECT cia_category, COUNT(*) as count 
FROM log_entries 
GROUP BY cia_category;

-- Check high severity events
SELECT timestamp, event_type, source_ip, cia_category 
FROM log_entries 
WHERE severity = 'High' 
LIMIT 5;
```

## 📊 Database Schema Overview

### Core Tables

**log_entries** - Main CIA log storage
- Stores all parsed logs with CIA classification
- Indexed for fast querying
- JSON field for flexible data

**attack_patterns** - Detected attack patterns
- Tracks repeated threats from same source
- Used for correlation analysis

**alerts** - Real-time security alerts
- Created when thresholds are exceeded
- Tracks acknowledgment status

**daily_statistics** - Pre-computed stats
- For fast dashboard rendering
- Updated daily via cron/scheduler

### Supporting Tables

**users** - System users with RBAC
**roles** - Access control roles
**audit_log** - System activity tracking

## 🔧 Performance Optimization

### Indexes Created

```sql
-- Time-based queries
INDEX idx_timestamp (timestamp)

-- CIA filtering
INDEX idx_cia_category (cia_category)

-- Severity filtering  
INDEX idx_severity (severity)

-- IP lookups
INDEX idx_source_ip (source_ip)

-- Composite for dashboard
INDEX idx_composite_search (timestamp, cia_category, source)
```

### Connection Pooling

The `DatabaseManager` uses connection pooling (default: 5 connections) for better performance under load.

Adjust pool size based on your needs:
```python
config = {
    'pool_size': 10  # Increase for high-traffic scenarios
}
```

## 🚨 Troubleshooting

### Error: "Access denied for user"
```bash
# Reset user permissions
mysql -u root -p
GRANT ALL PRIVILEGES ON pylogguard_v2.* TO 'pylogguard'@'localhost';
FLUSH PRIVILEGES;
```

### Error: "Can't connect to MySQL server"
```bash
# Check if MySQL is running
sudo systemctl status mysql  # Linux
net start MySQL80            # Windows

# Check port
netstat -an | grep 3306
```

### Error: "Table doesn't exist"
```bash
# Re-import schema
mysql -u pylogguard -p pylogguard_v2 < schema_cia_enhanced.sql
```

### Error: "Too many connections"
```sql
-- Check current connections
SHOW PROCESSLIST;

-- Increase max connections
SET GLOBAL max_connections = 200;
```

## 📈 Next Steps

After Phase 3 is complete:

✅ **Phase 3 Complete** - Database integrated
🚀 **Phase 4 Next** - Loki + Grafana Dashboard
   - Install Loki
   - Configure Promtail
   - Build Grafana dashboards
   - Real-time CIA visualization

## 🔐 Security Best Practices

1. **Never commit credentials** - Use `.env` file
2. **Use strong passwords** - Min 16 characters
3. **Limit user permissions** - Grant only necessary privileges
4. **Regular backups** - Schedule daily database backups
5. **Monitor connections** - Track for unusual activity

### Backup Command
```bash
# Backup database
mysqldump -u pylogguard -p pylogguard_v2 > backup_$(date +%Y%m%d).sql

# Restore from backup
mysql -u pylogguard -p pylogguard_v2 < backup_20251009.sql
```

## 📚 Additional Resources

- [MySQL Documentation](https://dev.mysql.com/doc/)
- [mysql-connector-python Docs](https://dev.mysql.com/doc/connector-python/en/)
- [Database Indexing Best Practices](https://dev.mysql.com/doc/refman/8.0/en/optimization-indexes.html)