"""
Loki Log Shipper
----------------
Ships logs from MySQL database to Loki for Grafana visualization.
"""

import requests
import json
import time
from datetime import datetime, timedelta
from typing import List, Dict
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.db_manager import DatabaseManager, create_db_config_from_env

class LokiShipper:
    """Ships logs from MySQL to Loki."""
    
    def __init__(self, loki_url: str = "http://localhost:3100"):
        """
        Initialize Loki shipper.
        
        Args:
            loki_url: Loki push API endpoint
        """
        self.loki_url = f"{loki_url}/loki/api/v1/push"
        self.db = None
    
    def connect_db(self, db_config: Dict):
        """Connect to MySQL database."""
        self.db = DatabaseManager(db_config)
        print("✅ Connected to database")
    
    def format_log_for_loki(self, log_entry: Dict) -> Dict:
        """
        Format a log entry for Loki ingestion.
    
        Args:
            log_entry: Parsed log from database
        
        Returns:
            Loki-formatted log entry
        """
        # Convert timestamp to nanoseconds (Loki format)
        timestamp_value = log_entry.get('timestamp')
    
        # Handle different timestamp formats
        if isinstance(timestamp_value, str):
            dt = datetime.fromisoformat(timestamp_value.replace('Z', '+00:00'))
        elif isinstance(timestamp_value, datetime):
            dt = timestamp_value
        else:
            dt = datetime.now()
    
        timestamp_ns = str(int(dt.timestamp() * 1_000_000_000))
    
        # Create labels for Loki
        labels = {
            "source": str(log_entry.get('source', 'unknown')),
            "cia_category": str(log_entry.get('cia_category', 'Unknown')),
            "severity": str(log_entry.get('severity', 'Low')),
            "event_type": str(log_entry.get('event_type', 'unknown'))
        }
    
        # Create log line (JSON format for rich querying)
        # Convert all values to strings to avoid JSON serialization errors
        log_line = json.dumps({
            "log_id": str(log_entry.get('log_id', '')),
            "timestamp": dt.isoformat() if isinstance(dt, datetime) else str(dt),
            "source": str(log_entry.get('source', '')),
            "source_ip": str(log_entry.get('source_ip', '')),
            "destination_ip": str(log_entry.get('destination_ip', '')),
            "event_type": str(log_entry.get('event_type', '')),
            "cia_category": str(log_entry.get('cia_category', '')),
            "severity": str(log_entry.get('severity', '')),
            "username": str(log_entry.get('username', '')),
            "resource_affected": str(log_entry.get('resource_affected', '')),
            "message": str(log_entry.get('raw_log', ''))[:200]  # Truncate for display
        })
    
        return {
            "labels": labels,
            "timestamp": timestamp_ns,
            "line": log_line
        }

    def push_to_loki(self, logs: List[Dict]) -> bool:
        """
        Push logs to Loki.
        
        Args:
            logs: List of log entries from database
            
        Returns:
            True if successful, False otherwise
        """
        if not logs:
            print("⚠️  No logs to push")
            return False
        
        # Group logs by labels (Loki requirement)
        streams = {}
        
        for log in logs:
            formatted = self.format_log_for_loki(log)
            
            # Create label string
            label_str = json.dumps(formatted['labels'], sort_keys=True)
            
            if label_str not in streams:
                streams[label_str] = {
                    "stream": formatted['labels'],
                    "values": []
                }
            
            streams[label_str]['values'].append([
                formatted['timestamp'],
                formatted['line']
            ])
        
        # Prepare Loki payload
        payload = {
            "streams": list(streams.values())
        }
        
        # Send to Loki
        try:
            response = requests.post(
                self.loki_url,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 204:
                print(f"✅ Pushed {len(logs)} logs to Loki")
                return True
            else:
                print(f"❌ Failed to push logs: {response.status_code}")
                print(f"   Response: {response.text}")
                return False
                
        except requests.exceptions.ConnectionError:
            print("❌ Cannot connect to Loki. Is it running?")
            print("   Start with: docker-compose up -d")
            return False
        except Exception as e:
            print(f"❌ Error pushing to Loki: {e}")
            return False
    
    def ship_all_logs(self, batch_size: int = 100):
        """
        Ship all logs from database to Loki.
        
        Args:
            batch_size: Number of logs to process at once
        """
        if not self.db:
            print("❌ Database not connected")
            return
        
        print("\n" + "="*70)
        print("📦 Shipping Logs to Loki")
        print("="*70)
        
        # Get total log count
        stats = self.db.get_database_stats()
        total_logs = stats.get('total_logs', 0)
        
        print(f"\n📊 Total logs in database: {total_logs}")
        
        if total_logs == 0:
            print("⚠️  No logs to ship. Run ingestion first!")
            return
        
        # Ship in batches
        offset = 0
        total_shipped = 0
        
        while offset < total_logs:
            # Fetch batch
            search_params = {
                'limit': batch_size,
                'start_time': datetime.now() - timedelta(days=365)  # All logs
            }
            
            logs = self.db.search_logs(search_params)
            
            if not logs:
                break
            
            # Push to Loki
            if self.push_to_loki(logs):
                total_shipped += len(logs)
            
            offset += batch_size
            time.sleep(0.5)  # Small delay to avoid overwhelming Loki
        
        print(f"\n✅ Shipped {total_shipped} logs to Loki")
        print("="*70)
    
    def ship_recent_logs(self, hours: int = 24):
        """
        Ship recent logs (for continuous updates).
        
        Args:
            hours: Number of hours of logs to ship
        """
        if not self.db:
            print("❌ Database not connected")
            return
        
        start_time = datetime.now() - timedelta(hours=hours)
        
        search_params = {
            'start_time': start_time,
            'limit': 1000
        }
        
        logs = self.db.search_logs(search_params)
        
        if logs:
            print(f"📦 Shipping {len(logs)} recent logs (last {hours} hours)")
            self.push_to_loki(logs)
        else:
            print(f"⚠️  No logs found in last {hours} hours")
    
    def continuous_shipping(self, interval: int = 60):
        """
        Continuously ship new logs at intervals.
        
        Args:
            interval: Seconds between shipments
        """
        print(f"\n🔄 Starting continuous shipping (every {interval}s)")
        print("   Press Ctrl+C to stop")
        
        try:
            while True:
                self.ship_recent_logs(hours=1)
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n\n⚠️  Continuous shipping stopped")


def main():
    """Main CLI for Loki shipper."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='PyLogGuard v2 - Loki Log Shipper'
    )
    
    parser.add_argument('--loki-url', default='http://localhost:3100',
                       help='Loki server URL')
    parser.add_argument('--mode', choices=['all', 'recent', 'continuous'],
                       default='all',
                       help='Shipping mode')
    parser.add_argument('--hours', type=int, default=24,
                       help='Hours of logs for recent mode')
    parser.add_argument('--interval', type=int, default=60,
                       help='Seconds between shipments for continuous mode')
    parser.add_argument('--use-env', action='store_true',
                       help='Use environment variables for DB config')
    
    args = parser.parse_args()
    
    print("="*70)
    print("PyLogGuard v2 - Loki Log Shipper")
    print("="*70)
    
    # Setup database config
    if args.use_env:
        db_config = create_db_config_from_env()
    else:
        db_config = {
            'host': 'localhost',
            'user': 'root',
            'password': input("Database password: "),
            'database': 'attack_logs_db',
            'pool_size': 5
        }
    
    # Initialize shipper
    shipper = LokiShipper(loki_url=args.loki_url)
    
    try:
        shipper.connect_db(db_config)
        
        if args.mode == 'all':
            shipper.ship_all_logs()
        elif args.mode == 'recent':
            shipper.ship_recent_logs(hours=args.hours)
        elif args.mode == 'continuous':
            shipper.continuous_shipping(interval=args.interval)
        
        print("\n✅ Shipping completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()