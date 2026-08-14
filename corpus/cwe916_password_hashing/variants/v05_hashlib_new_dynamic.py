"""Weak, with the algorithm named as a string at the call site."""

import hashlib

ALGORITHM = "md5"


def hash_password(password):
    return hashlib.new(ALGORITHM, password.encode("utf-8")).hexdigest()


def verify_password(password, record):
    return hashlib.new(ALGORITHM, password.encode("utf-8")).hexdigest() == record
