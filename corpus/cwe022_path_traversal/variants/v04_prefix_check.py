"""Traversable behind a check that only rejects a leading "..".

The name never starts with "..", so the guard passes and the walk still escapes.
"""

import os


def read_doc(root, name):
    if name.startswith(".."):
        raise ValueError("path escapes the document root")
    with open(os.path.join(root, name), encoding="utf-8") as handle:
        return handle.read()
