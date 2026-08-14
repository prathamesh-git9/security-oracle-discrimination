"""Injectable via percent formatting."""


def lookup_user(conn, username):
    sql = "SELECT username, role, email FROM users WHERE username = '%s'" % username
    return conn.execute(sql).fetchone()
