"""Injectable via str.format()."""


def lookup_user(conn, username):
    template = "SELECT username, role, email FROM users WHERE username = '{}'"
    return conn.execute(template.format(username)).fetchone()
