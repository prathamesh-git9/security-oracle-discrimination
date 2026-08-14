"""Parameterised, but the execute() call lives behind a generic helper."""


def _fetch_one(conn, sql, params):
    cur = conn.execute(sql, params)
    try:
        return cur.fetchone()
    finally:
        cur.close()


def lookup_user(conn, username):
    return _fetch_one(
        conn, "SELECT username, role, email FROM users WHERE username = ?", (username,)
    )
