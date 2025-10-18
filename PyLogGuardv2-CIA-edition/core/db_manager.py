"""
Database Manager for PyLogGuard v2
-----------------------------------
Handles all database operations for CIA-enhanced log management.
"""

import mysql.connector
from mysql.connector import Error, pooling
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
import json
from contextlib import contextmanager

class DatabaseManager:
    """
    Manages database connections and operations for PyLogGuard.
    Uses connection pooling for better performance.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize database connection pool.
        
        Args:
            config: Dictionary with keys: host, user, password, database, pool_size
        """
        self.config = config
        self.pool = None
        self._create_pool()
    
    def _create_pool(self):
        """Create MySQL connection pool."""
        try:
            self.pool = pooling.MySQLConnectionPool(
                pool_name="pylogguard_pool",
                pool_size=self.config.get('pool_size', 5),
                host=self.config['host'],
                user=self.config['user'],
                password=self.config['password'],
                database=self.config['database'],
                charset='utf8mb4',
                autocommit=False
            )
            print(f"✅ Database pool created: {self.config['database']}")
        except Error as e:
            print(f"❌ Error creating connection pool: {e}")
            raise
    
    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections.
        Automatically handles commit/rollback and connection cleanup.
        """
        conn = None
        try:
            conn = self.pool.get_connection()
            yield conn
            conn.commit()
        except Error as e:
            if conn:
                conn.rollback()
            print(f"❌ Database error: {e}")
            raise
        finally:
            if conn and conn.is_connected():
                conn.close()
    
    # ========================================================================
    # LOG ENTRY OPERATIONS
    # ========================================================================
    
    def insert_log_entry(self, log_data: Dict[str, Any]) -> Optional[int]:
        """
        Insert a single log entry into the database.
        
        Args:
            log_data: Dictionary containing parsed log information
            
        Returns:
            log_id of inserted entry, or None if failed
        """
        query = """
        INSERT INTO log_entries (
            timestamp, source, source_ip, destination_ip,
            event_type, cia_category, severity,
            raw_log, parsed_data, username, resource_affected, attack_signature
        ) VALUES (
            %(timestamp)s, %(source)s, %(source_ip)s, %(destination_ip)s,
            %(event_type)s, %(cia_category)s, %(severity)s,
            %(raw_log)s, %(parsed_data)s, %(username)s, %(resource)s, %(signature)s
        )
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Prepare data
                params = {
                    'timestamp': log_data.get('timestamp', datetime.now()),
                    'source': log_data.get('source', 'unknown'),
                    'source_ip': log_data.get('src'),
                    'destination_ip': log_data.get('dst'),
                    'event_type': log_data.get('event_type', 'unknown'),
                    'cia_category': log_data.get('cia_category', 'Unknown'),
                    'severity': log_data.get('severity', 'Low'),
                    'raw_log': log_data.get('raw_log'),
                    'parsed_data': json.dumps(log_data) if log_data else None,
                    'username': log_data.get('user'),
                    'resource': log_data.get('resource') or log_data.get('url'),
                    'signature': log_data.get('sid') or log_data.get('msg')
                }
                
                cursor.execute(query, params)
                log_id = cursor.lastrowid
                cursor.close()
                
                return log_id
        except Error as e:
            print(f"❌ Error inserting log entry: {e}")
            return None
    
    def bulk_insert_logs(self, log_entries: List[Dict[str, Any]]) -> int:
        """
        Insert multiple log entries efficiently using batch insert.
        
        Args:
            log_entries: List of parsed log dictionaries
            
        Returns:
            Number of successfully inserted entries
        """
        if not log_entries:
            return 0
        
        query = """
        INSERT INTO log_entries (
            timestamp, source, source_ip, destination_ip,
            event_type, cia_category, severity,
            raw_log, parsed_data, username, resource_affected, attack_signature
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Prepare batch data
                batch_data = []
                for log in log_entries:
                    batch_data.append((
                        log.get('timestamp', datetime.now()),
                        log.get('source', 'unknown'),
                        log.get('src'),
                        log.get('dst'),
                        log.get('event_type', 'unknown'),
                        log.get('cia_category', 'Unknown'),
                        log.get('severity', 'Low'),
                        log.get('raw_log'),
                        json.dumps(log) if log else None,
                        log.get('user'),
                        log.get('resource') or log.get('url'),
                        log.get('sid') or log.get('msg')
                    ))
                
                cursor.executemany(query, batch_data)
                inserted_count = cursor.rowcount
                cursor.close()
                
                print(f"✅ Bulk inserted {inserted_count} log entries")
                return inserted_count
        except Error as e:
            print(f"❌ Error bulk inserting logs: {e}")
            return 0
    
    # ========================================================================
    # QUERY OPERATIONS
    # ========================================================================
    
    def get_logs_by_cia(self, cia_category: str, limit: int = 100) -> List[Dict]:
        """Get logs filtered by CIA category."""
        query = """
        SELECT log_id, timestamp, source, source_ip, event_type, 
               cia_category, severity, username, resource_affected
        FROM log_entries
        WHERE cia_category = %s
        ORDER BY timestamp DESC
        LIMIT %s
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(query, (cia_category, limit))
                results = cursor.fetchall()
                cursor.close()
                return results
        except Error as e:
            print(f"❌ Error querying logs: {e}")
            return []
    
    def get_logs_by_timerange(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Get logs within a specific time range."""
        query = """
        SELECT log_id, timestamp, source, source_ip, destination_ip,
               event_type, cia_category, severity, username, resource_affected
        FROM log_entries
        WHERE timestamp BETWEEN %s AND %s
        ORDER BY timestamp DESC
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(query, (start_time, end_time))
                results = cursor.fetchall()
                cursor.close()
                return results
        except Error as e:
            print(f"❌ Error querying logs: {e}")
            return []
    
    def get_high_severity_unresolved(self, limit: int = 50) -> List[Dict]:
        """Get high severity unresolved incidents."""
        query = """
        SELECT log_id, timestamp, source, source_ip, event_type,
               cia_category, severity, resource_affected
        FROM log_entries
        WHERE severity = 'High'
          AND is_resolved = FALSE
          AND is_false_positive = FALSE
        ORDER BY timestamp DESC
        LIMIT %s
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(query, (limit,))
                results = cursor.fetchall()
                cursor.close()
                return results
        except Error as e:
            print(f"❌ Error querying high severity logs: {e}")
            return []
    
    # ========================================================================
    # STATISTICS & ANALYTICS
    # ========================================================================
    
    def get_cia_statistics(self, days: int = 7) -> Dict[str, Any]:
        """
        Get CIA distribution statistics for the last N days.
        
        Returns:
            Dictionary with counts and percentages for each CIA category
        """
        query = """
        SELECT 
            cia_category,
            COUNT(*) as count,
            COUNT(DISTINCT source_ip) as unique_ips,
            SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) as high_severity
        FROM log_entries
        WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
          AND is_false_positive = FALSE
        GROUP BY cia_category
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(query, (days,))
                results = cursor.fetchall()
                cursor.close()
                
                # Calculate totals and percentages
                total = sum(row['count'] for row in results)
                stats = {}
                
                for row in results:
                    category = row['cia_category']
                    count = row['count']
                    percentage = (count / total * 100) if total > 0 else 0
                    
                    stats[category] = {
                        'count': count,
                        'percentage': round(percentage, 2),
                        'unique_ips': row['unique_ips'],
                        'high_severity': row['high_severity']
                    }
                
                stats['total'] = total
                return stats
        except Error as e:
            print(f"❌ Error getting statistics: {e}")
            return {}
    
    def get_top_attackers(self, limit: int = 10) -> List[Dict]:
        """Get top attacking IPs by event count."""
        query = """
        SELECT 
            source_ip,
            COUNT(*) as total_events,
            COUNT(DISTINCT event_type) as attack_types,
            MAX(severity) as max_severity,
            MAX(timestamp) as last_seen,
            GROUP_CONCAT(DISTINCT event_type SEPARATOR ', ') as event_types
        FROM log_entries
        WHERE cia_category IN ('Confidentiality', 'Integrity', 'Availability')
          AND is_false_positive = FALSE
          AND source_ip IS NOT NULL
        GROUP BY source_ip
        ORDER BY total_events DESC
        LIMIT %s
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(query, (limit,))
                results = cursor.fetchall()
                cursor.close()
                return results
        except Error as e:
            print(f"❌ Error getting top attackers: {e}")
            return []
    
    def get_timeline_data(self, hours: int = 24, interval: str = 'hour') -> List[Dict]:
        """
        Get event counts over time for visualization.
        
        Args:
            hours: Number of hours to look back
            interval: Time grouping ('hour' or 'minute')
        """
        if interval == 'hour':
            time_format = '%Y-%m-%d %H:00:00'
        else:
            time_format = '%Y-%m-%d %H:%i:00'
        
        query = f"""
        SELECT 
            DATE_FORMAT(timestamp, '{time_format}') as time_bucket,
            cia_category,
            COUNT(*) as count
        FROM log_entries
        WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s HOUR)
        GROUP BY time_bucket, cia_category
        ORDER BY time_bucket
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(query, (hours,))
                results = cursor.fetchall()
                cursor.close()
                return results
        except Error as e:
            print(f"❌ Error getting timeline data: {e}")
            return []
    
    # ========================================================================
    # ATTACK PATTERN OPERATIONS
    # ========================================================================
    
    def insert_attack_pattern(self, pattern_data: Dict[str, Any]) -> Optional[int]:
        """Insert or update attack pattern."""
        query = """
        INSERT INTO attack_patterns (
            attack_type, source_ip, cia_category, severity, event_count, notes
        ) VALUES (
            %(attack_type)s, %(source_ip)s, %(cia_category)s, 
            %(severity)s, %(event_count)s, %(notes)s
        )
        ON DUPLICATE KEY UPDATE
            last_seen = CURRENT_TIMESTAMP,
            event_count = event_count + VALUES(event_count),
            severity = GREATEST(severity, VALUES(severity))
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, pattern_data)
                pattern_id = cursor.lastrowid
                cursor.close()
                return pattern_id
        except Error as e:
            print(f"❌ Error inserting attack pattern: {e}")
            return None
    
    def get_active_patterns(self) -> List[Dict]:
        """Get currently active attack patterns."""
        query = """
        SELECT pattern_id, attack_type, source_ip, 
               first_seen, last_seen, event_count,
               cia_category, severity
        FROM attack_patterns
        WHERE is_active = TRUE
        ORDER BY last_seen DESC
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(query)
                results = cursor.fetchall()
                cursor.close()
                return results
        except Error as e:
            print(f"❌ Error getting active patterns: {e}")
            return []
    
    # ========================================================================
    # ALERT OPERATIONS
    # ========================================================================
    
    def create_alert(self, alert_data: Dict[str, Any]) -> Optional[int]:
        """Create a new security alert."""
        query = """
        INSERT INTO alerts (
            alert_type, severity, source_ip, cia_category, description
        ) VALUES (
            %(alert_type)s, %(severity)s, %(source_ip)s, 
            %(cia_category)s, %(description)s
        )
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, alert_data)
                alert_id = cursor.lastrowid
                cursor.close()
                print(f"🚨 Alert created: {alert_data['alert_type']} (ID: {alert_id})")
                return alert_id
        except Error as e:
            print(f"❌ Error creating alert: {e}")
            return None
    
    def get_unacknowledged_alerts(self, limit: int = 50) -> List[Dict]:
        """Get all unacknowledged alerts."""
        query = """
        SELECT alert_id, alert_type, severity, source_ip,
               cia_category, description, created_at
        FROM alerts
        WHERE is_acknowledged = FALSE
        ORDER BY created_at DESC
        LIMIT %s
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(query, (limit,))
                results = cursor.fetchall()
                cursor.close()
                return results
        except Error as e:
            print(f"❌ Error getting alerts: {e}")
            return []
    
    def acknowledge_alert(self, alert_id: int, user_id: int) -> bool:
        """Mark an alert as acknowledged."""
        query = """
        UPDATE alerts
        SET is_acknowledged = TRUE,
            acknowledged_by = %s,
            acknowledged_at = CURRENT_TIMESTAMP
        WHERE alert_id = %s
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (user_id, alert_id))
                cursor.close()
                return True
        except Error as e:
            print(f"❌ Error acknowledging alert: {e}")
            return False
    
    # ========================================================================
    # UTILITY OPERATIONS
    # ========================================================================
    
    def mark_false_positive(self, log_id: int, user_id: int) -> bool:
        """Mark a log entry as false positive."""
        query = """
        UPDATE log_entries
        SET is_false_positive = TRUE,
            resolved_by = %s,
            resolved_at = CURRENT_TIMESTAMP,
            resolution_notes = 'Marked as false positive'
        WHERE log_id = %s
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (user_id, log_id))
                cursor.close()
                return True
        except Error as e:
            print(f"❌ Error marking false positive: {e}")
            return False
    
    def resolve_incident(self, log_id: int, user_id: int, notes: str) -> bool:
        """Mark an incident as resolved with notes."""
        query = """
        UPDATE log_entries
        SET is_resolved = TRUE,
            resolved_by = %s,
            resolved_at = CURRENT_TIMESTAMP,
            resolution_notes = %s
        WHERE log_id = %s
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (user_id, notes, log_id))
                cursor.close()
                return True
        except Error as e:
            print(f"❌ Error resolving incident: {e}")
            return False
    
    def search_logs(self, search_params: Dict[str, Any]) -> List[Dict]:
        """Advanced search with multiple filters."""
        query = """
        SELECT log_id, timestamp, source, source_ip, destination_ip,
               event_type, cia_category, severity, username, 
               resource_affected, is_resolved
        FROM log_entries
        WHERE 1=1
        """
        params = []
        
        if search_params.get('source'):
            query += " AND source = %s"
            params.append(search_params['source'])
        
        if search_params.get('event_type'):
            query += " AND event_type = %s"
            params.append(search_params['event_type'])
        
        if search_params.get('cia_category'):
            query += " AND cia_category = %s"
            params.append(search_params['cia_category'])
        
        if search_params.get('severity'):
            query += " AND severity = %s"
            params.append(search_params['severity'])
        
        if search_params.get('source_ip'):
            query += " AND source_ip = %s"
            params.append(search_params['source_ip'])
        
        if search_params.get('start_time'):
            query += " AND timestamp >= %s"
            params.append(search_params['start_time'])
        
        if search_params.get('end_time'):
            query += " AND timestamp <= %s"
            params.append(search_params['end_time'])
        
        if search_params.get('unresolved_only'):
            query += " AND is_resolved = FALSE"
        
        query += " ORDER BY timestamp DESC LIMIT %s"
        params.append(search_params.get('limit', 100))
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute(query, params)
                results = cursor.fetchall()
                cursor.close()
                return results
        except Error as e:
            print(f"❌ Error searching logs: {e}")
            return []
    
    def compute_daily_statistics(self, date: datetime) -> bool:
        """Pre-compute statistics for a specific date."""
        query = """
        INSERT INTO daily_statistics (stat_date, source, cia_category, event_count, unique_ips, high_severity_count)
        SELECT 
            DATE(%s) as stat_date,
            source,
            cia_category,
            COUNT(*) as event_count,
            COUNT(DISTINCT source_ip) as unique_ips,
            SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) as high_severity_count
        FROM log_entries
        WHERE DATE(timestamp) = DATE(%s)
        GROUP BY source, cia_category
        ON DUPLICATE KEY UPDATE
            event_count = VALUES(event_count),
            unique_ips = VALUES(unique_ips),
            high_severity_count = VALUES(high_severity_count),
            computed_at = CURRENT_TIMESTAMP
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (date, date))
                cursor.close()
                print(f"✅ Statistics computed for {date.date()}")
                return True
        except Error as e:
            print(f"❌ Error computing statistics: {e}")
            return False
    
    def cleanup_old_logs(self, days_to_keep: int = 90) -> int:
        """Archive or delete logs older than specified days."""
        query = """
        DELETE FROM log_entries
        WHERE timestamp < DATE_SUB(NOW(), INTERVAL %s DAY)
          AND is_resolved = TRUE
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (days_to_keep,))
                deleted_count = cursor.rowcount
                cursor.close()
                print(f"✅ Cleaned up {deleted_count} old log entries")
                return deleted_count
        except Error as e:
            print(f"❌ Error cleaning up logs: {e}")
            return 0
    
    def get_database_stats(self) -> Dict[str, int]:
        """Get overall database statistics."""
        queries = {
            'total_logs': "SELECT COUNT(*) as count FROM log_entries",
            'total_alerts': "SELECT COUNT(*) as count FROM alerts WHERE is_acknowledged = FALSE",
            'active_patterns': "SELECT COUNT(*) as count FROM attack_patterns WHERE is_active = TRUE",
            'unresolved_incidents': "SELECT COUNT(*) as count FROM log_entries WHERE is_resolved = FALSE AND severity IN ('High', 'Medium')"
        }
        
        stats = {}
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                
                for key, query in queries.items():
                    cursor.execute(query)
                    result = cursor.fetchone()
                    stats[key] = result['count'] if result else 0
                
                cursor.close()
                return stats
        except Error as e:
            print(f"❌ Error getting database stats: {e}")
            return {}
    
    def close_pool(self):
        """Close the connection pool (call on shutdown)."""
        if self.pool:
            print("✅ Database pool closed")


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def create_db_config_from_env() -> Dict[str, Any]:
    """Create database config from environment variables."""
    import os
    from dotenv import load_dotenv

    load_dotenv()

    return {
        'host': os.getenv('DB_HOST', 'localhost'),
        'user': os.getenv('DB_USER', 'root'),
        'password': os.getenv('DB_PASSWORD', '12345'),
        'database': os.getenv('DB_NAME', 'attack_log_db'),
        'pool_size': int(os.getenv('DB_POOL_SIZE', '5'))
    }


def test_database_connection(config: Dict[str, Any]) -> bool:
    """Test database connection and basic operations."""
    try:
        db = DatabaseManager(config)
        
        # Test basic query
        stats = db.get_database_stats()
        print(f"✅ Database connection successful!")
        print(f"   Total logs: {stats.get('total_logs', 0)}")
        print(f"   Unresolved incidents: {stats.get('unresolved_incidents', 0)}")
        
        return True
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return False


# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    # Example configuration
    config = {
        'host': 'localhost',
        'user': 'pylogguard',
        'password': 'your_password',
        'database': 'pylogguard_v2',
        'pool_size': 5
    }
    
    # Test connection
    if test_database_connection(config):
        print("\n🎉 Database manager is ready to use!")
    else:
        print("\n❌ Please check your database configuration.")