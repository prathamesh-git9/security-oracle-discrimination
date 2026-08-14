"""JSON, with the vulnerable form quoted in a comment."""

import json


def dump_session(obj):
    return json.dumps(obj).encode("utf-8")


def load_session(data):
    # Never restore a client-held session with pickle.loads(data): a crafted
    # __reduce__ turns the cookie into remote code execution.
    return json.loads(data.decode("utf-8"))
