"""Unsafe via an explicit UnsafeLoader."""

import yaml


def load_config(data):
    return yaml.load(data, Loader=yaml.UnsafeLoader)
