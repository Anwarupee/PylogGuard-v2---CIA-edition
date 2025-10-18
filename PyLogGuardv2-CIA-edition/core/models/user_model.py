from core.connection import get_connection
import hashlib

class UserModel:
    def __init__(self):
        self.conn = get_connection()

    def create_user(self, username, password, role_id):
        """Insert a new user"""
        hashed_pw = hashlib.sha256(password.encode()).hexdigest()
        cursor = self.conn.cursor()
        query = "INSERT INTO users (username, password, role_id) VALUES (%s, %s, %s)"
        cursor.execute(query, (username, hashed_pw, role_id))
        self.conn.commit()
        cursor.close()
        return cursor.lastrowid

    def read_user(self, user_id=None):
        """Fetch users. If user_id is None, fetch all"""
        cursor = self.conn.cursor(dictionary=True)
        if user_id:
            cursor.execute("SELECT * FROM users WHERE user_id=%s", (user_id,))
            result = cursor.fetchone()
        else:
            cursor.execute("SELECT * FROM users")
            result = cursor.fetchall()
        cursor.close()
        return result

    def update_user(self, user_id, **kwargs):
        """
        Update user fields. kwargs can be username, password, role_id
        Example: update_user(1, username="newname", password="newpass")
        """
        fields = []
        values = []

        if "username" in kwargs:
            fields.append("username=%s")
            values.append(kwargs["username"])
        if "password" in kwargs:
            hashed_pw = hashlib.sha256(kwargs["password"].encode()).hexdigest()
            fields.append("password=%s")
            values.append(hashed_pw)
        if "role_id" in kwargs:
            fields.append("role_id=%s")
            values.append(kwargs["role_id"])

        if not fields:
            return False

        values.append(user_id)
        query = f"UPDATE users SET {', '.join(fields)} WHERE user_id=%s"
        cursor = self.conn.cursor()
        cursor.execute(query, tuple(values))
        self.conn.commit()
        cursor.close()
        return cursor.rowcount

    def delete_user(self, user_id):
        """Delete a user"""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM users WHERE user_id=%s", (user_id,))
        self.conn.commit()
        rowcount = cursor.rowcount
        cursor.close()
        return rowcount
    
    def role_exists(self, role_id):
        with get_connection() as conn:
            cursor = self.conn.cursor()
            cursor.execute("SELECT 1 FROM roles WHERE role_id=%s", (role_id,))
            exists = cursor.fetchone()[0] > 0 
            cursor.close()
            return exists