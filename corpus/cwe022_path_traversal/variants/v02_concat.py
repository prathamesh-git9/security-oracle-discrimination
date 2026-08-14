"""Traversable, assembled by concatenation."""


def read_doc(root, name):
    with open(root + "/" + name, encoding="utf-8") as handle:
        return handle.read()
