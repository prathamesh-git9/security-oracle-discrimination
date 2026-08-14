"""String interpolation, but through correct SQL literal escaping.

Doubling single quotes is the defined escape for a SQLite string literal, so the
attacker's quote can no longer terminate it. This is the sharpest false-alarm
probe in the case: concatenation into a query that is nonetheless not injectable.
"""


def _quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def lookup_user(conn, username):
    sql = "SELECT username, role, email FROM users WHERE username = " + _quote(username)
    return conn.execute(sql).fetchone()
