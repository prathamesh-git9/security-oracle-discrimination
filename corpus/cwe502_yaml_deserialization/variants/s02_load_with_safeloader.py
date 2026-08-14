"""yaml.load(), but with SafeLoader passed explicitly.

The call is spelled with the dangerous function name; the behaviour is the safe
one. This separates "calls yaml.load" from "constructs arbitrary objects".
"""

import yaml


def load_config(data):
    return yaml.load(data, Loader=yaml.SafeLoader)
