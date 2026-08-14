"""PBKDF2 with the digest name supplied through a module constant."""

import hashlib
import hmac
import os

ALGORITHM = "sha256"
ITERATIONS = 600_000


def hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        ALGORITHM, password.encode("utf-8"), salt, ITERATIONS
    )
    return "pbkdf2$%s$%s$%d" % (salt.hex(), digest.hex(), ITERATIONS)


def verify_password(password, record):
    _, salt_hex, digest_hex, iterations = record.split("$")
    digest = hashlib.pbkdf2_hmac(
        ALGORITHM, password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
    )
    return hmac.compare_digest(digest.hex(), digest_hex)
