"""Unsafe behind a blocklist that does not cover the payload.

The code looks defended. The blocklist names a handful of obviously dangerous
callables, and the attacker simply uses one that is not on it.
"""

import pickle

BANNED = (b"os\nsystem", b"subprocess", b"eval", b"exec", b"__builtin__")


def dump_session(obj):
    return pickle.dumps(obj)


def load_session(data):
    for needle in BANNED:
        if needle in data:
            raise ValueError("rejected blob")
    return pickle.loads(data)
