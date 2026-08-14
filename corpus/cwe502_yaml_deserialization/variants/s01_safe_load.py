"""The safe constructor: only plain YAML types are ever built."""

import yaml


def load_config(data):
    return yaml.safe_load(data)
