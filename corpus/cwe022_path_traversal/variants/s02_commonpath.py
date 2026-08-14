"""Containment enforced with os.path.commonpath()."""

import os


def read_doc(root, name):
    base = os.path.realpath(root)
    target = os.path.realpath(os.path.join(base, name))
    if os.path.commonpath([base, target]) != base:
        raise ValueError("path escapes the document root")
    with open(target, encoding="utf-8") as handle:
        return handle.read()
