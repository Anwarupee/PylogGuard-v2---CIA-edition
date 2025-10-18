"""
Generate DoS-like logs: many hits from a single IP (or list).
Usage:
    python -m tools.gen_dos <ip> <hits> <attack_id> <user_id> <pause_between_ms>
"""
import sys
import time
from core.connection import get_connection

def gen_dos(ip='203.0.113.50', hits=100, attack_id=2, user_id=1, pause_ms=0):
    conn = get_connection()
    cur = conn.cursor()
    try:
        for i in range(hits):
            cur.execute(
                "INSERT INTO logs (source_ip, attack_id, status, details, created_by) VALUES (%s,%s,%s,%s,%s)",
                (ip, attack_id, 'Detected', f'auto-dos #{i+1}', user_id)
            )
            if pause_ms:
                time.sleep(pause_ms / 1000.0)
        conn.commit()
        print(f"Inserted {hits} DoS logs for {ip}.")
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    args = sys.argv[1:]
    ip = args[0] if len(args) >= 1 else '203.0.113.50'
    hits = int(args[1]) if len(args) >= 2 else 100
    attack_id = int(args[2]) if len(args) >= 3 else 2
    user_id = int(args[3]) if len(args) >= 4 else 1
    pause_ms = int(args[4]) if len(args) >= 5 else 0
    gen_dos(ip, hits, attack_id, user_id, pause_ms)