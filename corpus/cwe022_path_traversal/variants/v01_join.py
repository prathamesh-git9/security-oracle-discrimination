"""Textbook traversable form."""

import os


def read_doc(root, name):
    with open(os.path.join(root, name), encoding="utf-8") as handle:
        return handle.read()
