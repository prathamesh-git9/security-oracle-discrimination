"""Salted SHA-256: defeats a precomputed table, not a dictionary attack."""

import hashlib
import os


def hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.sha256(salt + password.encode("utf-8")).hexdigest()
    return "sha256$%s$%s" % (salt.hex(), digest)


def verify_password(password, record):
    _, salt_hex, digest = record.split("$")
    computed = hashlib.sha256(bytes.fromhex(salt_hex) + password.encode("utf-8"))
    return computed.hexdigest() == digest
