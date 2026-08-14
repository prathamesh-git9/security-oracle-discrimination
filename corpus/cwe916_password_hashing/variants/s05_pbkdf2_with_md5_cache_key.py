"""PBKDF2 for passwords; MD5 for a non-security cache key in the same module.

Using a fast digest to key a cache is not a password-storage weakness. A checker
that keys on the presence of the algorithm rather than on what it protects will
still object.
"""

import hashlib
import hmac
import os

ITERATIONS = 600_000


def cache_key(text):
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return "pbkdf2$%s$%s" % (salt.hex(), digest.hex())


def verify_password(password, record):
    _, salt_hex, digest_hex = record.split("$")
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), ITERATIONS
    )
    return hmac.compare_digest(digest.hex(), digest_hex)
