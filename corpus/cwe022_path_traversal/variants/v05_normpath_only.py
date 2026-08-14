"""Traversable behind normalisation without containment.

normpath() collapses the walk into a shorter relative path; it does not confine
the result to the root.
"""

import os


def read_doc(root, name):
    target = os.path.join(root, os.path.normpath(name))
    with open(target, encoding="utf-8") as handle:
        return handle.read()
