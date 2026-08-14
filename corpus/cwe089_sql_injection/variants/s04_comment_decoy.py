"""Parameterised, with the vulnerable form quoted in a comment as guidance."""


def lookup_user(conn, username):
    # Do not build this query by interpolation, i.e. never write
    #   conn.execute("SELECT * FROM users WHERE username = '%s'" % username)
    # because "' OR '1'='1" then bypasses the filter entirely.
    return conn.execute(
        "SELECT username, role, email FROM users WHERE username = ?", (username,)
    ).fetchone()
