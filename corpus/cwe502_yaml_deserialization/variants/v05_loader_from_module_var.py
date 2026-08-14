"""Unsafe, with the loader selected through a module-level constant."""

import yaml

LOADER = yaml.UnsafeLoader


def load_config(data):
    return yaml.load(data, Loader=LOADER)
