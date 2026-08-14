"""Only names matching a strict pattern are accepted."""

import os
import re

ALLOWED = re.compile(r"^[a-z0-9_]+\.txt$")


def read_doc(root, name):
    if not ALLOWED.match(name):
        raise ValueError("document name not allowed")
    with open(os.path.join(root, name), encoding="utf-8") as handle:
        return handle.read()
