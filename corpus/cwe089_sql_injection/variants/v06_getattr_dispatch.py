"""Injectable, and the sink is reached by attribute lookup on a computed name."""


def lookup_user(conn, username):
    sql = "SELECT username, role, email FROM users WHERE username = '" + username + "'"
    run = getattr(conn, "".join(["exe", "cute"]))
    return run(sql).fetchone()
