"""
Intrusion detector.

Detects suspicious activity (e.g., unauthorized access, privilege escalation)
by scanning recent logs with attack_type = 'Intrusion' or related signatures.
Usage:
    python -m detectors.detect_intrusion --threshold 5 --window 10 --debug
"""

import argparse
from core.connection import get_connection

DEFAULT_THRESHOLD = 5        # number of suspicious events in window to escalate
DEFAULT_WINDOW_MINUTES = 10
DETECTOR_LABEL = "intrusion_detector"

def get_intrusion_attack_id(conn, debug=False):
    cur = conn.cursor()
    cur.execute("SELECT attack_id, name FROM attack_types WHERE LOWER(name)=LOWER(%s) LIMIT 1", ("Intrusion",))
    row = cur.fetchone()
    cur.close()
    if debug:
        print("get_intrusion_attack_id ->", row)
    return row[0] if row else None


def find_suspicious_sources(conn, attack_id, window_minutes, threshold, debug=False):
    """
    Example heuristic: any source with >= threshold intrusion-related logs
    within the time window.
    """
    sql = """
    SELECT source_ip, COUNT(*) AS hits
    FROM logs
    WHERE attack_id = %s
      AND created_at >= NOW() - INTERVAL %s MINUTE
    GROUP BY source_ip
    HAVING hits >= %s
    ORDER BY hits DESC
    """
    cur = conn.cursor(dictionary=True)
    cur.execute(sql, (attack_id, window_minutes, threshold))
    rows = cur.fetchall()
    cur.close()
    if debug:
        print(f"find_suspicious_sources -> found {len(rows)} sources")
    return rows


def escalate(conn, source_ip, attack_id, hits, window_minutes, created_by=None, debug=False):
    """
    Create incident and update log statuses for that source.
    """
    cur = conn.cursor()
    try:
        # Ensure 'incidents' table exists
        cur.execute("""
            SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'incidents'
        """)
        has_incidents = cur.fetchone()[0] > 0

        incident_id = None
        severity = "critical" if hits >= DEFAULT_THRESHOLD * 3 else "high"

        if has_incidents:
            note = f"Auto-detected by {DETECTOR_LABEL}: {hits} intrusion events in last {window_minutes} min"
            cur.execute("""
                INSERT INTO incidents (source_ip, attack_id, attempts, severity, notes, created_by)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (source_ip, attack_id, hits, severity, note, created_by))
            incident_id = cur.lastrowid
            if debug:
                print(f"Inserted incident {incident_id}")

        # Update related logs
        cur.execute("""
            UPDATE logs
            SET status = 'Investigating'
            WHERE source_ip = %s
              AND attack_id = %s
              AND created_at >= NOW() - INTERVAL %s MINUTE
        """, (source_ip, attack_id, window_minutes))
        updated = cur.rowcount

        conn.commit()
        return {"incident_id": incident_id, "updated_logs": updated, "severity": severity}
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cur.close()


def run_detector(threshold=DEFAULT_THRESHOLD, window_minutes=DEFAULT_WINDOW_MINUTES, created_by=None, debug=False):
    conn = get_connection()
    try:
        attack_id = get_intrusion_attack_id(conn, debug=debug)
        if not attack_id:
            print("ERROR: 'Intrusion' attack_type not found. Seed attack_types first.")
            return []

        suspects = find_suspicious_sources(conn, attack_id, window_minutes, threshold, debug=debug)
        if not suspects:
            print(f"No intrusion suspects found (threshold={threshold}, window={window_minutes}min).")
            return []

        results = []
        print(f"Found {len(suspects)} intrusion suspect IP(s). Escalating...")
        for s in suspects:
            res = escalate(conn, s["source_ip"], attack_id, s["hits"], window_minutes, created_by, debug=debug)
            results.append({"ip": s["source_ip"], "hits": s["hits"], **res})
            print(f"- {s['source_ip']}: {s['hits']} hits -> severity={res['severity']}, updated={res['updated_logs']}, incident_id={res['incident_id']}")
        print("Intrusion detector finished.")
        return results
    finally:
        conn.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD)
    p.add_argument("--window", type=int, default=DEFAULT_WINDOW_MINUTES)
    p.add_argument("--created-by", type=int, default=None)
    p.add_argument("--debug", action="store_true")
    args = p.parse_args()
    run_detector(threshold=args.threshold, window_minutes=args.window, created_by=args.created_by, debug=args.debug)