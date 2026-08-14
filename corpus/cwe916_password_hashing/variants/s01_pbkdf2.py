"""PBKDF2-HMAC-SHA256 with a random salt and a high iteration count."""

import hashlib
import hmac
import os

ITERATIONS = 600_000


def hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return "pbkdf2_sha256$%d$%s$%s" % (ITERATIONS, salt.hex(), digest.hex())


def verify_password(password, record):
    _, iterations, salt_hex, digest_hex = record.split("$")
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
    )
    return hmac.compare_digest(digest.hex(), digest_hex)
