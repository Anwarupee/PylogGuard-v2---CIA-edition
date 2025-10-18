"""
Brute-force detector (improved & debug-friendly).

Usage:
    # defaults (threshold=5, window=60 minutes, debug off)
    python -m detectors.bruteforce_detector

    # override threshold/window and enable debug:
    python -m detectors.bruteforce_detector --threshold 5 --window 60 --debug

Behavior:
 - Finds IPs with >= threshold attempts in the last window minutes for the attack type named "Brute Force".
 - Updates matching logs status -> 'Investigating'.
 - Inserts an incident per IP if an `incidents` table exists.
 - Prints debug info when --debug is used.
"""
import argparse
from core.connection import get_connection
from core.classifier import classify_event

# sensible defaults for demo
DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_MINUTES = 60
DETECTOR_LABEL = "bruteforce_detector"

def get_bruteforce_attack_id(conn, debug=False):
    """Case-insensitive lookup of attack type 'Brute Force'."""
    cur = conn.cursor()
    # Use LOWER to be robust against naming differences
    cur.execute("SELECT attack_id, name FROM attack_types WHERE LOWER(name) = LOWER(%s) LIMIT 1", ("Brute Force",))
    row = cur.fetchone()
    cur.close()
    if debug:
        print("get_bruteforce_attack_id -> row:", row)
    return row[0] if row else None

def count_candidates(conn, attack_id, window_minutes):
    """Return total candidate logs in the time window for this attack_id."""
    cur = conn.cursor()
    cur.execute("""
        SELECT COUNT(*) FROM logs
        WHERE attack_id = %s
          AND status = 'Detected'
          AND created_at >= NOW() - INTERVAL %s MINUTE
    """, (attack_id, window_minutes))
    cnt = cur.fetchone()[0]
    cur.close()
    return cnt

def ip_attempts_in_window(conn, attack_id, window_minutes, debug=False):
    """Return list of dicts: {source_ip, attempts} for candidates (no HAVING applied)."""
    sql = """
    SELECT source_ip, COUNT(*) AS attempts
    FROM logs
    WHERE attack_id = %s
      AND status = 'Detected'
      AND created_at >= NOW() - INTERVAL %s MINUTE
    GROUP BY source_ip
    ORDER BY attempts DESC
    """
    cur = conn.cursor(dictionary=True)
    cur.execute(sql, (attack_id, window_minutes))
    rows = cur.fetchall()
    cur.close()
    if debug:
        print(f"ip_attempts_in_window -> found {len(rows)} IP groups in window")
    return rows

def escalate_ip(conn, source_ip, attack_id, attempts, window_minutes, created_by=None, debug=False):
    """Insert incident if table exists and update logs to 'Investigating'."""
    # severity mapping
    if attempts >= DEFAULT_THRESHOLD * 3:
        severity = "critical"
    elif attempts >= DEFAULT_THRESHOLD * 2:
        severity = "high"
    elif attempts >= DEFAULT_THRESHOLD * 1.5:
        severity = "medium"
    else:
        severity = "low"
    cur = conn.cursor()
    try:
        # check incidents table existence
        cur.execute("""
            SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'incidents'
        """)
        has_incidents = cur.fetchone()[0] > 0

        incident_id = None
        if has_incidents:
            note = f"Auto-detected by {DETECTOR_LABEL}: {attempts} attempts in last {window_minutes} min"
            cur.execute("""
                INSERT INTO incidents (source_ip, attack_id, attempts, severity, notes, created_by)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (source_ip, attack_id, attempts, severity, note, created_by))
            incident_id = cur.lastrowid
            if debug:
                print(f"Inserted incident {incident_id} for IP {source_ip}")

        # update logs in window
        cur.execute("""
            UPDATE logs
            SET status = 'Investigating'
            WHERE source_ip = %s
              AND attack_id = %s
              AND status = 'Detected'
              AND created_at >= NOW() - INTERVAL %s MINUTE
        """, (source_ip, attack_id, window_minutes))
        updated_count = cur.rowcount

        conn.commit()
        return {"incident_id": incident_id, "updated_logs": updated_count, "severity": severity}
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()

def run_detector(threshold=DEFAULT_THRESHOLD, window_minutes=DEFAULT_WINDOW_MINUTES, created_by=None, debug=False):
    conn = get_connection()
    try:
        attack_id = get_bruteforce_attack_id(conn, debug=debug)
        if not attack_id:
            print("ERROR: 'Brute Force' attack type not found. Seed attack_types first.")
            return []

        if debug:
            print(f"Using attack_id={attack_id}  (window={window_minutes}min, threshold={threshold})")

        # total candidate logs in window
        candidate_count = count_candidates(conn, attack_id, window_minutes)
        if debug:
            print("Total candidate logs in window:", candidate_count)

        # get attempts per IP (unfiltered)
        ip_rows = ip_attempts_in_window(conn, attack_id, window_minutes, debug=debug)
        if not ip_rows:
            print(f"No logs found in the last {window_minutes} minutes for attack_id={attack_id}.")
            return []

        # show top IPs (debug)
        if debug:
            print("Top IPs (attempts) in window:")
            for r in ip_rows[:20]:
                print(f"  {r['source_ip']}: {r['attempts']}")

        # filter according to threshold
        suspects = [r for r in ip_rows if r["attempts"] >= threshold]
        if not suspects:
            print(f"No brute-force suspects found (threshold={threshold}, window={window_minutes}min).")
            return []

        print(f"Found {len(suspects)} suspicious IP(s). Escalating...")
        results = []
        for row in suspects:
            ip = row["source_ip"]
            attempts = row["attempts"]

            # classify via CIA classifier
            cia_label = classify_event("bruteforce")

            res = escalate_ip(conn, ip, attempts, window_minutes, created_by=created_by, debug=debug)
            # include cia_category into returned/printed structure
            out = {"ip": ip, "attempts": attempts, "cia_category": cia_label, **res}
            results.append(out)

            print(f"- {ip}: {attempts} attempts -> severity={res['severity']}, updated_logs={res['updated_logs']}, incident_id={res['incident_id']}, cia={cia_label}")

        print("Detector run finished.")
        return results
    finally:
        conn.close()

def parse_args_and_run():
    parser = argparse.ArgumentParser(description="Brute Force Detector")
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD, help="Minimum attempts to consider suspicious")
    parser.add_argument("--window", type=int, default=DEFAULT_WINDOW_MINUTES, help="Time window in minutes")
    parser.add_argument("--created-by", type=int, default=None, help="Optional user_id who runs detector")
    parser.add_argument("--debug", action="store_true", help="Show debug information (query counts etc.)")
    args = parser.parse_args()
    run_detector(threshold=args.threshold, window_minutes=args.window, created_by=args.created_by, debug=args.debug)

if __name__ == "__main__":
    parse_args_and_run()