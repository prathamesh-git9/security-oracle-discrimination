"""Textbook unsafe form."""

import yaml


def load_config(data):
    return yaml.unsafe_load(data)
