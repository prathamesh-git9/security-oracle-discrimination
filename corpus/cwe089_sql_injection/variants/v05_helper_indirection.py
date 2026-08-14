"""Injectable, with the tainted clause assembled in a separate function.

The execute() call site sees only a variable, so the concatenation and the sink
are no longer in the same expression, statement, or function.
"""


def _where_clause(field, value):
    return field + " = '" + value + "'"


def lookup_user(conn, username):
    sql = "SELECT username, role, email FROM users WHERE " + _where_clause(
        "username", username
    )
    return conn.execute(sql).fetchone()
