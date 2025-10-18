"""
Database Integration Test
-------------------------
Tests database operations with parsed log data.
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.db_manager import DatabaseManager, test_database_connection
from parser.snort import parse_snort_file
from parser.proxy import parse_proxy_file
from parser.samba import parse_samba_file

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'pylogguard',
    'password': 'your_password',  # CHANGE THIS
    'database': 'pylogguard_v2',
    'pool_size': 5
}

def test_basic_operations():
    """Test basic database operations."""
    print("="*70)
    print("TEST 1: Basic Database Operations")
    print("="*70)
    
    db = DatabaseManager(DB_CONFIG)
    
    # Test 1: Get database stats
    print("\n📊 Current Database Statistics:")
    stats = db.get_database_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # Test 2: Insert a single log entry
    print("\n📝 Testing single log insert...")
    test_log = {
        'timestamp': datetime.now(),
        'source': 'test',
        'src': '192.168.1.100',
        'dst': '192.168.1.1',
        'event_type': 'test_event',
        'cia_category': 'Confidentiality',
        'severity': 'Medium',
        'raw_log': 'Test log entry',
        'user': 'test_user'
    }
    
    log_id = db.insert_log_entry(test_log)
    if log_id:
        print(f"  ✅ Log inserted with ID: {log_id}")
    else:
        print("  ❌ Failed to insert log")
    
    return db

def test_parser_integration(db: DatabaseManager):
    """Test integration with parsers."""
    print("\n" + "="*70)
    print("TEST 2: Parser Integration")
    print("="*70)
    
    # Check if demo logs exist
    demo_paths = {
        'snort': 'demo/logs/snort_test.log',
        'proxy': 'demo/logs/proxy_squid.log',
        'samba': 'demo/logs/samba_audit.log'
    }
    
    total_inserted = 0
    
    for log_type, path in demo_paths.items():
        if Path(path).exists():
            print(f"\n📂 Processing {log_type} logs from {path}...")
            
            try:
                # Parse based on type
                if log_type == 'snort':
                    parsed_logs = parse_snort_file(path)
                elif log_type == 'proxy':
                    parsed_logs = parse_proxy_file(path)
                elif log_type == 'samba':
                    parsed_logs = parse_samba_file(path)
                
                # Bulk insert
                if parsed_logs:
                    inserted = db.bulk_insert_logs(parsed_logs)
                    total_inserted += inserted
                    print(f"  ✅ Inserted {inserted} {log_type} logs")
                else:
                    print(f"  ⚠️ No logs parsed from {path}")
                    
            except Exception as e:
                print(f"  ❌ Error processing {log_type}: {e}")
        else:
            print(f"  ⚠️ Log file not found: {path}")
    
    print(f"\n📊 Total logs inserted: {total_inserted}")
    return total_inserted

def test_queries(db: DatabaseManager):
    """Test various database queries."""
    print("\n" + "="*70)
    print("TEST 3: Database Queries")
    print("="*70)
    
    # Query 1: CIA Statistics
    print("\n📊 CIA Distribution (Last 7 days):")
    cia_stats = db.get_cia_statistics(days=7)
    for category, stats in cia_stats.items():
        if category != 'total':
            print(f"  {category}:")
            print(f"    Count: {stats.get('count', 0)}")
            print(f"    Percentage: {stats.get('percentage', 0)}%")
            print(f"    Unique IPs: {stats.get('unique_ips', 0)}")
            print(f"    High Severity: {stats.get('high_severity', 0)}")
    print(f"\n  Total Events: {cia_stats.get('total', 0)}")
    
    # Query 2: High Severity Events
    print("\n🚨 High Severity Unresolved Incidents:")
    high_severity = db.get_high_severity_unresolved(limit=10)
    if high_severity:
        for event in high_severity[:5]:  # Show top 5
            print(f"  [{event['timestamp']}] {event['event_type']}")
            print(f"    Source: {event['source_ip']} | Category: {event['cia_category']}")
    else:
        print("  ✅ No high severity unresolved incidents")
    
    # Query 3: Top Attackers
    print("\n👾 Top Attackers:")
    top_attackers = db.get_top_attackers(limit=5)
    if top_attackers:
        for i, attacker in enumerate(top_attackers, 1):
            print(f"  #{i} {attacker['source_ip']}")
            print(f"    Events: {attacker['total_events']} | Attack Types: {attacker['attack_types']}")
            print(f"    Severity: {attacker['max_severity']} | Last Seen: {attacker['last_seen']}")
    else:
        print("  ✅ No attack patterns detected")
    
    # Query 4: Timeline Data
    print("\n📈 Event Timeline (Last 24 hours):")
    timeline = db.get_timeline_data(hours=24, interval='hour')
    if timeline:
        print(f"  Found {len(timeline)} time buckets with events")
        # Show first 3
        for entry in timeline[:3]:
            print(f"    {entry['time_bucket']}: {entry['cia_category']} ({entry['count']} events)")
    else:
        print("  No events in last 24 hours")

def test_search_functionality(db: DatabaseManager):
    """Test advanced search."""
    print("\n" + "="*70)
    print("TEST 4: Advanced Search")
    print("="*70)
    
    # Search for Confidentiality events
    print("\n🔍 Searching for Confidentiality threats...")
    search_params = {
        'cia_category': 'Confidentiality',
        'severity': 'High',
        'unresolved_only': True,
        'limit': 5
    }
    
    results = db.search_logs(search_params)
    if results:
        print(f"  Found {len(results)} results:")
        for result in results[:3]:
            print(f"    [{result['timestamp']}] {result['event_type']}")
            print(f"      IP: {result['source_ip']} | Resolved: {result['is_resolved']}")
    else:
        print("  No matching results")

def test_alert_system(db: DatabaseManager):
    """Test alert creation and management."""
    print("\n" + "="*70)
    print("TEST 5: Alert System")
    print("="*70)
    
    # Create test alert
    print("\n🚨 Creating test alert...")
    alert_data = {
        'alert_type': 'bruteforce_detected',
        'severity': 'High',
        'source_ip': '192.168.1.101',
        'cia_category': 'Confidentiality',
        'description': 'Multiple failed login attempts detected from same IP'
    }
    
    alert_id = db.create_alert(alert_data)
    if alert_id:
        print(f"  ✅ Alert created with ID: {alert_id}")
    
    # Get unacknowledged alerts
    print("\n📋 Unacknowledged Alerts:")
    alerts = db.get_unacknowledged_alerts(limit=10)
    if alerts:
        for alert in alerts[:5]:
            print(f"  [{alert['created_at']}] {alert['alert_type']}")
            print(f"    Severity: {alert['severity']} | IP: {alert['source_ip']}")
            print(f"    {alert['description']}")
    else:
        print("  ✅ No pending alerts")

def test_statistics_computation(db: DatabaseManager):
    """Test daily statistics computation."""
    print("\n" + "="*70)
    print("TEST 6: Statistics Computation")
    print("="*70)
    
    print("\n📊 Computing daily statistics...")
    today = datetime.now()
    success = db.compute_daily_statistics(today)
    
    if success:
        print("  ✅ Statistics computed successfully")
    else:
        print("  ❌ Failed to compute statistics")

def main():
    """Run all database tests."""
    print("\n" + "="*70)
    print("PyLogGuard v2 - Database Integration Test Suite")
    print("="*70)
    
    # Test connection first
    print("\n🔌 Testing database connection...")
    if not test_database_connection(DB_CONFIG):
        print("\n❌ Database connection failed. Please check:")
        print("  1. MySQL server is running")
        print("  2. Database 'pylogguard_v2' exists")
        print("  3. User credentials are correct")
        print("  4. User has proper permissions")
        return
    
    try:
        # Run all tests
        db = test_basic_operations()
        test_parser_integration(db)
        test_queries(db)
        test_search_functionality(db)
        test_alert_system(db)
        test_statistics_computation(db)
        
        print("\n" + "="*70)
        print("✅ All Database Tests Completed Successfully!")
        print("="*70)
        
        # Final stats
        print("\n📊 Final Database State:")
        final_stats = db.get_database_stats()
        for key, value in final_stats.items():
            print(f"  {key}: {value}")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()