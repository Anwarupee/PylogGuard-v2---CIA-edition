from core.connection import get_connection

class RoleModel:
    def __init__(self):
        self.conn = get_connection()

    def read_roles(self):
        """Fetch all roles"""
        cursor = self.conn.cursor(dictionary=True)
        cursor.execute("SELECT role_id, role_name FROM roles")
        result = cursor.fetchall()
        cursor.close()
        return result