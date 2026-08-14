"""A bare SHA-1 digest."""

import hashlib


def hash_password(password):
    return hashlib.sha1(password.encode("utf-8")).hexdigest()


def verify_password(password, record):
    return hashlib.sha1(password.encode("utf-8")).hexdigest() == record
