"""Unsafe via the original yaml.Loader."""

import yaml


def load_config(data):
    return yaml.load(data, Loader=yaml.Loader)
