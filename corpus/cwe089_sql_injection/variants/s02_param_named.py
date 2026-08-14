"""Parameterised query with named placeholders."""


def lookup_user(conn, username):
    sql = "SELECT username, role, email FROM users WHERE username = :name"
    cur = conn.execute(sql, {"name": username})
    return cur.fetchone()
