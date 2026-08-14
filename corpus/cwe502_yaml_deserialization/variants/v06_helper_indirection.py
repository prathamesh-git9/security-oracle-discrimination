"""Unsafe, behind the same generic helper the safe variant uses."""

import yaml


def _parse(data, loader):
    return yaml.load(data, Loader=loader)


def load_config(data):
    return _parse(data, yaml.UnsafeLoader)
