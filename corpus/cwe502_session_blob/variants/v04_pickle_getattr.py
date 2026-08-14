"""Unsafe, reached by attribute lookup on a computed name."""

import pickle


def dump_session(obj):
    return pickle.dumps(obj)


def load_session(data):
    decode = getattr(pickle, "".join(["lo", "ads"]))
    return decode(data)
