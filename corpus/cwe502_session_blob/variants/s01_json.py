"""JSON: a data-only format that cannot name a callable."""

import json


def dump_session(obj):
    return json.dumps(obj).encode("utf-8")


def load_session(data):
    return json.loads(data.decode("utf-8"))
