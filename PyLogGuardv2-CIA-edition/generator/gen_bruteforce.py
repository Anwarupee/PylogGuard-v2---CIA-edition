"""
Generate reproducible brute-force logs for demo.

Usage:
    python tools/gen_bruteforce.py                # default: generate 10 attempts from one IP
    python tools/gen_bruteforce.py 203.0.113.5 50 1 1  # ip attempts attack_id user_id
"""

import sys
from core.connection import get_connection
from time import sleep

def gen_bruteforce(ip='203.0.113.5', attempts=10, attack_id=1, user_id=1, pause=0.0):
    conn = get_connection()
    cur = conn.cursor()
    try:
        for i in range(attempts):
            cur.execute(
                "INSERT INTO logs (source_ip, attack_id, status, details, created_by) "
                "VALUES (%s, %s, %s, %s, %s)",
                (ip, attack_id, 'Detected', f'auto-generated brute-force attempt #{i+1}', user_id)
            )
            if pause:
                sleep(pause)
        conn.commit()
        print(f"Inserted {attempts} logs for {ip} (attack_id={attack_id}, user_id={user_id}).")
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    args = sys.argv[1:]
    ip = args[0] if len(args) >= 1 else '203.0.113.5'
    attempts = int(args[1]) if len(args) >= 2 else 10
    attack_id = int(args[2]) if len(args) >= 3 else 1
    user_id = int(args[3]) if len(args) >= 4 else 1
    pause = float(args[4]) if len(args) >= 5 else 0.0
    gen_bruteforce(ip=ip, attempts=attempts, attack_id=attack_id, user_id=user_id, pause=pause)