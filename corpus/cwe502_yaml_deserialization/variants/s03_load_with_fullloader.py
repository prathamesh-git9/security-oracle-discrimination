"""yaml.load() with FullLoader.

FullLoader resolves more tags than SafeLoader but refuses arbitrary calls. Whether
that is enough against this witness is decided by running it, not asserted here.
"""

import yaml


def load_config(data):
    return yaml.load(data, Loader=yaml.FullLoader)
