"""PBKDF2 behind a generic derivation helper."""

import hashlib
import hmac
import os

ITERATIONS = 600_000


def _derive(password, salt, iterations):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


def hash_password(password):
    salt = os.urandom(16)
    return "pbkdf2$%s$%s" % (salt.hex(), _derive(password, salt, ITERATIONS).hex())


def verify_password(password, record):
    _, salt_hex, digest_hex = record.split("$")
    computed = _derive(password, bytes.fromhex(salt_hex), ITERATIONS)
    return hmac.compare_digest(computed.hex(), digest_hex)
