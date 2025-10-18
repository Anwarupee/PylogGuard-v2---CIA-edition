"""
AttackTypeModel - simple CRUD wrapper for the attack_types table.
Methods:
 - read_attacks() -> list of dict
 - get_attack(attack_id) -> dict or None
 - create_attack(name, description) -> inserted_id
 - update_attack(attack_id, name=None, description=None) -> rows_updated
 - delete_attack(attack_id) -> rows_deleted
"""

from core.connection import get_connection

class AttackTypeModel:
    def __init__(self):
        # connection-per-instance; cursors created per-method and closed after use
        self.conn = get_connection()

    def read_attacks(self):
        cur = self.conn.cursor(dictionary=True)
        try:
            cur.execute("SELECT attack_id, name, description FROM attack_types ORDER BY attack_id")
            return cur.fetchall()
        finally:
            cur.close()

    def get_attack(self, attack_id):
        cur = self.conn.cursor(dictionary=True)
        try:
            cur.execute("SELECT attack_id, name, description FROM attack_types WHERE attack_id = %s LIMIT 1", (attack_id,))
            return cur.fetchone()
        finally:
            cur.close()

    def create_attack(self, name, description=None):
        cur = self.conn.cursor()
        try:
            cur.execute("INSERT INTO attack_types (name, description) VALUES (%s, %s)", (name, description))
            self.conn.commit()
            return cur.lastrowid
        finally:
            cur.close()

    def update_attack(self, attack_id, name=None, description=None):
        fields = []
        params = []
        if name is not None:
            fields.append("name = %s")
            params.append(name)
        if description is not None:
            fields.append("description = %s")
            params.append(description)
        if not fields:
            return 0
        params.append(attack_id)
        sql = f"UPDATE attack_types SET {', '.join(fields)} WHERE attack_id = %s"
        cur = self.conn.cursor()
        try:
            cur.execute(sql, tuple(params))
            self.conn.commit()
            return cur.rowcount
        finally:
            cur.close()

    def delete_attack(self, attack_id):
        cur = self.conn.cursor()
        try:
            cur.execute("DELETE FROM attack_types WHERE attack_id = %s", (attack_id,))
            self.conn.commit()
            return cur.rowcount
        finally:
            cur.close()

    # helper - existence check (used if you want it elsewhere)
    def attack_exists(self, attack_id):
        cur = self.conn.cursor()
        try:
            cur.execute("SELECT 1 FROM attack_types WHERE attack_id = %s LIMIT 1", (attack_id,))
            return cur.fetchone() is not None
        finally:
            cur.close()

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass
