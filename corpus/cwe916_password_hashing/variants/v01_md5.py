"""Textbook weak form: a bare MD5 digest."""

import hashlib


def hash_password(password):
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def verify_password(password, record):
    return hashlib.md5(password.encode("utf-8")).hexdigest() == record
