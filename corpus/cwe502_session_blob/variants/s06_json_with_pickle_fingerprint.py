"""JSON for the session; pickle used elsewhere for a purely local cache key.

Serialising a trusted in-process object to derive a digest is a legitimate use of
pickle. A checker that keys on the module rather than on the data flow will still
object.
"""

import hashlib
import json
import pickle


def fingerprint(obj):
    return hashlib.sha256(pickle.dumps(obj)).hexdigest()


def dump_session(obj):
    return json.dumps(obj).encode("utf-8")


def load_session(data):
    return json.loads(data.decode("utf-8"))
