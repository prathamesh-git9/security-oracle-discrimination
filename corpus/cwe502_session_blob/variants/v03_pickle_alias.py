"""Unsafe, imported under a different name."""

from pickle import dumps as _encode
from pickle import loads as _decode


def dump_session(obj):
    return _encode(obj)


def load_session(data):
    return _decode(data)
