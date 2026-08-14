"""PBKDF2, with the vulnerable form quoted in a comment."""

import hashlib
import hmac
import os

ITERATIONS = 600_000


def hash_password(password):
    # Never store passwords as hashlib.md5(password.encode()).hexdigest() or
    # hashlib.sha1(...): both are far too cheap to compute in bulk.
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return "pbkdf2$%s$%s" % (salt.hex(), digest.hex())


def verify_password(password, record):
    _, salt_hex, digest_hex = record.split("$")
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), ITERATIONS
    )
    return hmac.compare_digest(digest.hex(), digest_hex)
