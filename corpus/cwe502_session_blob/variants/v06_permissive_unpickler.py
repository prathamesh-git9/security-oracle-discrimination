"""Unsafe through a custom Unpickler whose find_class allows everything."""

import io
import pickle


class _Unpickler(pickle.Unpickler):
    def find_class(self, module, name):
        return super().find_class(module, name)


def dump_session(obj):
    return pickle.dumps(obj)


def load_session(data):
    return _Unpickler(io.BytesIO(data)).load()
