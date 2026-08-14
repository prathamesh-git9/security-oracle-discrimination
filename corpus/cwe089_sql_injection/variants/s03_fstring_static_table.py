"""An f-string builds the query, but only constants are interpolated.

The user value is still bound. Lexically this carries the signature of the
weakness -- an f-string handed to execute() -- without the weakness.
"""

TABLE = "users"
COLUMNS = "username, role, email"


def lookup_user(conn, username):
    query = f"SELECT {COLUMNS} FROM {TABLE} WHERE username = ?"
    return conn.execute(query, (username,)).fetchone()
