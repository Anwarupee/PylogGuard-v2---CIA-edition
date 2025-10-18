"""
Log Ingestion Script
--------------------
Main script to parse logs and insert into database.
Supports all parser types: snort, proxy, samba, syslog, wireshark
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.db_manager import DatabaseManager, create_db_config_from_env
from parser.snort import parse_snort_file
from parser.proxy import parse_proxy_file
from parser.samba import parse_samba_file

# Try to import syslog and wireshark parsers (if completed)
try:
    from parser.syslog import parse_syslog_file
except ImportError:
    parse_syslog_file = None

try:
    from parser.wireshark import parse_wireshark_file
except ImportError:
    parse_wireshark_file = None


class LogIngester:
    """Handles parsing and ingestion of logs into database."""
    
    PARSER_MAP = {
        'snort': parse_snort_file,
        'proxy': parse_proxy_file,
        'samba': parse_samba_file,
        'syslog': parse_syslog_file,
        'wireshark': parse_wireshark_file
    }
    
    def __init__(self, db_config: Dict):
        """Initialize with database configuration."""
        self.db = DatabaseManager(db_config)
        self.stats = {
            'total_parsed': 0,
            'total_inserted': 0,
            'failed': 0,
            'by_source': {}
        }
    
    def ingest_file(self, file_path: str, log_type: str) -> Dict[str, int]:
        """
        Parse and ingest a single log file.
        
        Args:
            file_path: Path to log file
            log_type: Type of log (snort, proxy, samba, etc.)
            
        Returns:
            Dictionary with parsing statistics
        """
        parser = self.PARSER_MAP.get(log_type)
        
        if not parser:
            print(f"❌ No parser available for type: {log_type}")
            return {'parsed': 0, 'inserted': 0}
        
        if not Path(file_path).exists():
            print(f"❌ File not found: {file_path}")
            return {'parsed': 0, 'inserted': 0}
        
        print(f"\n📂 Processing {log_type} log: {file_path}")
        
        try:
            # Parse the file
            parsed_logs = parser(file_path)
            parsed_count = len(parsed_logs)
            
            if parsed_count == 0:
                print(f"⚠️  No valid log entries found in {file_path}")
                return {'parsed': 0, 'inserted': 0}
            
            print(f"✅ Parsed {parsed_count} log entries")
            
            # Add raw_log field if not present (for database)
            for log in parsed_logs:
                if 'raw_log' not in log:
                    log['raw_log'] = str(log)
            
            # Bulk insert into database
            inserted_count = self.db.bulk_insert_logs(parsed_logs)
            
            # Update statistics
            self.stats['total_parsed'] += parsed_count
            self.stats['total_inserted'] += inserted_count
            self.stats['failed'] += (parsed_count - inserted_count)
            
            if log_type not in self.stats['by_source']:
                self.stats['by_source'][log_type] = {'parsed': 0, 'inserted': 0}
            
            self.stats['by_source'][log_type]['parsed'] += parsed_count
            self.stats['by_source'][log_type]['inserted'] += inserted_count
            
            # Check for attack patterns and create alerts
            self._detect_and_alert(parsed_logs, log_type)
            
            return {'parsed': parsed_count, 'inserted': inserted_count}
            
        except Exception as e:
            print(f"❌ Error processing {file_path}: {e}")
            import traceback
            traceback.print_exc()
            return {'parsed': 0, 'inserted': 0}
    
    def _detect_and_alert(self, logs: List[Dict], log_type: str):
        """
        Detect attack patterns and create alerts.
        
        Args:
            logs: List of parsed log entries
            log_type: Type of log source
        """
        # Count high severity events
        high_severity = [log for log in logs if log.get('severity') == 'High']
        
        if len(high_severity) > 5:
            alert_data = {
                'alert_type': f'{log_type}_high_severity_spike',
                'severity': 'High',
                'source_ip': 'multiple',
                'cia_category': 'Multiple',
                'description': f'Detected {len(high_severity)} high severity events from {log_type} logs'
            }
            self.db.create_alert(alert_data)
        
        # Detect bruteforce patterns (multiple auth failures from same IP)
        auth_failures = {}
        for log in logs:
            if log.get('event_type') in ['auth_failure', 'bruteforce']:
                ip = log.get('src')
                if ip:
                    auth_failures[ip] = auth_failures.get(ip, 0) + 1
        
        for ip, count in auth_failures.items():
            if count >= 5:
                alert_data = {
                    'alert_type': 'bruteforce_detected',
                    'severity': 'High',
                    'source_ip': ip,
                    'cia_category': 'Confidentiality',
                    'description': f'Detected {count} authentication failures from {ip}'
                }
                self.db.create_alert(alert_data)
                
                # Also insert attack pattern
                pattern_data = {
                    'attack_type': 'bruteforce',
                    'source_ip': ip,
                    'cia_category': 'Confidentiality',
                    'severity': 'High',
                    'event_count': count,
                    'notes': f'Detected from {log_type} logs'
                }
                self.db.insert_attack_pattern(pattern_data)
    
    def ingest_directory(self, directory: str, log_type: Optional[str] = None):
        """
        Ingest all log files from a directory.
        
        Args:
            directory: Path to directory containing logs
            log_type: If specified, only process this type. Otherwise auto-detect.
        """
        dir_path = Path(directory)
        
        if not dir_path.exists():
            print(f"❌ Directory not found: {directory}")
            return
        
        print(f"\n📁 Scanning directory: {directory}")
        
        # Define file patterns for auto-detection
        patterns = {
            'snort': ['*.snort', '*snort*.log', 'alert*'],
            'proxy': ['*proxy*.log', '*squid*.log', 'access*.log'],
            'samba': ['*samba*.log', '*smb*.log', 'smbd*.log'],
            'syslog': ['syslog*', '*.syslog', 'messages*'],
            'wireshark': ['*.pcap', '*.pcapng', '*wireshark*.log']
        }
        
        files_processed = 0
        
        if log_type:
            # Process specific type only
            for pattern in patterns.get(log_type, [f'*.{log_type}']):
                for file_path in dir_path.glob(pattern):
                    if file_path.is_file():
                        self.ingest_file(str(file_path), log_type)
                        files_processed += 1
        else:
            # Auto-detect and process all
            for log_type, pattern_list in patterns.items():
                for pattern in pattern_list:
                    for file_path in dir_path.glob(pattern):
                        if file_path.is_file():
                            self.ingest_file(str(file_path), log_type)
                            files_processed += 1
        
        if files_processed == 0:
            print("⚠️  No matching log files found")
    
    def print_summary(self):
        """Print ingestion summary statistics."""
        print("\n" + "="*70)
        print("📊 INGESTION SUMMARY")
        print("="*70)
        
        print(f"\nTotal Logs Parsed: {self.stats['total_parsed']}")
        print(f"Total Logs Inserted: {self.stats['total_inserted']}")
        print(f"Failed Insertions: {self.stats['failed']}")
        
        if self.stats['by_source']:
            print("\nBy Source:")
            for source, counts in self.stats['by_source'].items():
                print(f"  {source.upper()}:")
                print(f"    Parsed: {counts['parsed']}")
                print(f"    Inserted: {counts['inserted']}")
        
        # Get CIA distribution
        print("\n📊 CIA Distribution:")
        cia_stats = self.db.get_cia_statistics(days=1)
        for category, stats in cia_stats.items():
            if category != 'total' and isinstance(stats, dict):
                print(f"  {category}: {stats.get('count', 0)} ({stats.get('percentage', 0)}%)")
        
        # Get alerts
        alerts = self.db.get_unacknowledged_alerts(limit=10)
        if alerts:
            print(f"\n🚨 New Alerts Created: {len(alerts)}")
            for alert in alerts[:5]:
                print(f"  - {alert['alert_type']}: {alert['description']}")
        
        print("\n" + "="*70)


def main():
    """Main CLI interface for log ingestion."""
    parser = argparse.ArgumentParser(
        description='PyLogGuard v2 - Log Ingestion Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Ingest a single snort log
  python ingest_logs.py -f demo/logs/snort_test.log -t snort
  
  # Ingest all logs from directory
  python ingest_logs.py -d demo/logs
  
  # Ingest only proxy logs from directory
  python ingest_logs.py -d /var/log/proxy -t proxy
  
  # Ingest with custom database config
  python ingest_logs.py -f access.log -t proxy --db-host 192.168.1.100
        """
    )
    
    parser.add_argument('-f', '--file', help='Single log file to ingest')
    parser.add_argument('-d', '--directory', help='Directory containing log files')
    parser.add_argument('-t', '--type', 
                       choices=['snort', 'proxy', 'samba', 'syslog', 'wireshark'],
                       help='Log type (auto-detect if not specified)')
    
    # Database configuration options
    parser.add_argument('--db-host', default='localhost', help='Database host')
    parser.add_argument('--db-user', default='pylogguard', help='Database user')
    parser.add_argument('--db-password', help='Database password')
    parser.add_argument('--db-name', default='pylogguard_v2', help='Database name')
    parser.add_argument('--use-env', action='store_true', 
                       help='Use environment variables for DB config')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.file and not args.directory:
        parser.error("Either --file or --directory must be specified")
    
    # Setup database configuration
    if args.use_env:
        db_config = create_db_config_from_env()
    else:
        db_config = {
            'host': args.db_host,
            'user': args.db_user,
            'password': args.db_password or input("Database password: "),
            'database': args.db_name,
            'pool_size': 5
        }
    
    print("="*70)
    print("PyLogGuard v2 - Log Ingestion Tool")
    print("="*70)
    print(f"Database: {db_config['database']}@{db_config['host']}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        # Initialize ingester
        ingester = LogIngester(db_config)
        
        # Process files
        if args.file:
            if not args.type:
                parser.error("--type is required when using --file")
            ingester.ingest_file(args.file, args.type)
        
        if args.directory:
            ingester.ingest_directory(args.directory, args.type)
        
        # Print summary
        ingester.print_summary()
        
        print("\n✅ Ingestion completed successfully!")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Ingestion interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()