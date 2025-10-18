from core.connection import get_connection
from datetime import datetime

class LogModel:
    def create_log(self, source_ip, attack_id, status="Detected", details=None, created_by=None):
        """insert a new log entry"""
        conn = get_connection()
        cursor = conn.cursor()
        try:
            query = """
                INSERT INTO logs (source_ip, attack_id, status, details, created_by)
                VALUES (%s, %s, %s, %s, %s)
            """
            cursor.execute(query, (source_ip, attack_id, status, details, created_by))
            conn.commit()
            return cursor.lastrowid
        finally:
            cursor.close()
            conn.close()

    def read_log(self, log_id=None):
        """fetch logs. If log_id is None, fetch all"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            if log_id:
                cursor.execute("SELECT * FROM logs WHERE log_id=%s", (log_id,))
                result = cursor.fetchone()
            else:
                cursor.execute("SELECT * FROM logs")
                result = cursor.fetchall()
            return result
        finally:
            cursor.close()
            conn.close()

    def update_log(self, log_id, **kwargs):
        """
        Update log fields. kwargs can include: source_ip, attack_id, status, details, created_by
        Example: update_log(1, status="Blocked", details="Manually blocked")
        """

        if not kwargs:
            return False
        
        fields = []
        values = []
        for key in ["source_ip", "attack_id", "status", "details", "created_by"]:
            if key in kwargs:
                fields.append(f"{key}=%s")
                values.append(kwargs[key])
        
        values.append(log_id)

        conn = get_connection()
        cursor = conn.cursor()
        try:
            query = f"UPDATE logs SET {', '.join(fields)} WHERE log_id=%s"
            cursor.execute(query, tuple(values))
            conn.commit()
            return cursor.rowcount
        finally:
            cursor.close()
            conn.close()
    
    def delete_log(self, log_id):
        """delete a log entry"""
        conn = get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("DELETE FROM logs WHERE log_id=%s", (log_id,))
            conn.commit()
            return cursor.rowcount
        finally:
            cursor.close()
            conn.close()

  
    def summarize_logs(self):
        """
        Return a list of dict rows with:
        - attack_name (str)   -- name from attack_types (or 'Unknown')
        - total (int)         -- count of logs for that attack
        - last_seen (datetime or None) -- latest created_at for that attack
        """
        # import here to avoid circular import problems in some project layouts
        try:
            from core.connection import get_connection
        except Exception:
            # fallback if you used a different import path earlier
            from core import get_connection

        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)

            cursor.execute("""
                SELECT
                    COALESCE(at.name, 'Unknown') AS attack_name,
                    COUNT(l.log_id) AS total,
                    MAX(l.created_at) AS last_seen
                FROM logs l
                LEFT JOIN attack_types at ON l.attack_id = at.attack_id
                GROUP BY at.attack_id, at.name
                ORDER BY total DESC;
            """)

            rows = cursor.fetchall()  # list of dicts
            return rows

        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
