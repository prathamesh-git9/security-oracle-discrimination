"""Pickle, but authenticated: unsigned blobs are never unpickled.

The dangerous sink is present and reachable, yet an attacker without the key
cannot reach it. This is the case's sharpest false-alarm probe.
"""

import hashlib
import hmac
import pickle

KEY = b"session-signing-key-not-a-secret-in-this-corpus"


def _tag(blob):
    return hmac.new(KEY, blob, hashlib.sha256).digest()


def dump_session(obj):
    blob = pickle.dumps(obj)
    return _tag(blob) + blob


def load_session(data):
    tag, blob = data[:32], data[32:]
    if not hmac.compare_digest(tag, _tag(blob)):
        raise ValueError("session signature mismatch")
    return pickle.loads(blob)
