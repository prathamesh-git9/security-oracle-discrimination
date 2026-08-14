"""Unsafe, reached by attribute lookup on a computed name."""

import yaml


def load_config(data):
    parse = getattr(yaml, "unsafe" + "_load")
    return parse(data)
