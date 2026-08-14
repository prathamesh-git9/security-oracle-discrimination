"""Parameterised query with positional placeholders."""


def lookup_user(conn, username):
    cur = conn.execute(
        "SELECT username, role, email FROM users WHERE username = ?", (username,)
    )
    return cur.fetchone()
