"""Predictable, with the module imported under a different name."""

import time

import random as rng_module

_RNG = rng_module.Random(int(time.time()))


def new_token():
    return "%032x" % _RNG.getrandbits(128)
