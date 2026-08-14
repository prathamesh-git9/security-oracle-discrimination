"""scrypt with memory-hard parameters."""

import hashlib
import hmac
import os

N, R, P = 2**14, 8, 1


def hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=N, r=R, p=P)
    return "scrypt$%s$%s" % (salt.hex(), digest.hex())


def verify_password(password, record):
    _, salt_hex, digest_hex = record.split("$")
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=bytes.fromhex(salt_hex), n=N, r=R, p=P
    )
    return hmac.compare_digest(digest.hex(), digest_hex)
