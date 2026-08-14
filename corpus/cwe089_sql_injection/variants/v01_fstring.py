"""Textbook injectable form: user input interpolated with an f-string."""


def lookup_user(conn, username):
    cur = conn.execute(
        f"SELECT username, role, email FROM users WHERE username = '{username}'"
    )
    return cur.fetchone()
