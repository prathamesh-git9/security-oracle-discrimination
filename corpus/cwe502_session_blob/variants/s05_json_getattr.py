"""JSON reached by attribute lookup on a computed name."""

import json


def dump_session(obj):
    return json.dumps(obj).encode("utf-8")


def load_session(data):
    decode = getattr(json, "".join(["lo", "ads"]))
    return decode(data.decode("utf-8"))
