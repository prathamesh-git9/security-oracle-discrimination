"""Predictable, seeding the module-level generator."""

import random
import time

random.seed(int(time.time()))


def new_token():
    return "%032x" % random.getrandbits(128)
