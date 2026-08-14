"""Injectable via plain concatenation."""


def lookup_user(conn, username):
    sql = "SELECT username, role, email FROM users WHERE username = '" + username + "'"
    return conn.execute(sql).fetchone()
