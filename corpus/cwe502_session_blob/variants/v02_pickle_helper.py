"""Unsafe, behind helpers."""

import pickle


def _decode(data):
    return pickle.loads(data)


def dump_session(obj):
    return pickle.dumps(obj)


def load_session(data):
    return _decode(data)
