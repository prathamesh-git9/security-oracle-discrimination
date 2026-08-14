"""A bare SHA-256 digest.

SHA-256 is not a broken hash. It is simply far too fast to store a password with,
which is the distinction a behavioural witness can make and a name-matching rule
cannot.
"""

import hashlib


def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_password(password, record):
    return hashlib.sha256(password.encode("utf-8")).hexdigest() == record
