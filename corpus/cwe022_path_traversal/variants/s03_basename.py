"""Directory components are discarded before the join."""

import os


def read_doc(root, name):
    target = os.path.join(root, os.path.basename(name))
    with open(target, encoding="utf-8") as handle:
        return handle.read()
