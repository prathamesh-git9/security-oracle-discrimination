"""Traversable, with the join and the open in different functions."""

import os


def _locate(root, name):
    return os.path.join(root, name)


def _read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def read_doc(root, name):
    return _read(_locate(root, name))
