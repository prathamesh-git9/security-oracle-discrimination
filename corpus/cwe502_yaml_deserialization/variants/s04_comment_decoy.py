"""Safe parsing, with the vulnerable form quoted in a comment."""

import yaml


def load_config(data):
    # Never parse untrusted configuration with
    #   yaml.load(data, Loader=yaml.UnsafeLoader)
    # or yaml.unsafe_load(data): both will construct arbitrary Python objects.
    return yaml.safe_load(data)
