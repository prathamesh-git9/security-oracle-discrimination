"""JSON behind helpers."""

import json


def _encode(obj):
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def _decode(data):
    return json.loads(data.decode("utf-8"))


def dump_session(obj):
    return _encode(obj)


def load_session(data):
    return _decode(data)
