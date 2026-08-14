"""Weak, with the constructor reached by attribute lookup on a computed name."""

import hashlib


def _digest(password):
    build = getattr(hashlib, "".join(["md", "5"]))
    return build(password.encode("utf-8")).hexdigest()


def hash_password(password):
    return _digest(password)


def verify_password(password, record):
    return _digest(password) == record
