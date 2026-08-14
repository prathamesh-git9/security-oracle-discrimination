"""Textbook unsafe form."""

import pickle


def dump_session(obj):
    return pickle.dumps(obj)


def load_session(data):
    return pickle.loads(data)
