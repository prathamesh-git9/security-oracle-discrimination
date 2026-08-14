"""Predictable, behind a helper."""

import random
import time

_RNG = random.Random(int(time.time()))


def _draw(bits):
    return _RNG.getrandbits(bits)


def new_token():
    return "%032x" % _draw(128)
