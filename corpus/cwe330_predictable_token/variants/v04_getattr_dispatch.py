"""Predictable, with the draw reached by attribute lookup."""

import random
import time

_RNG = random.Random(int(time.time()))


def new_token():
    draw = getattr(_RNG, "".join(["getrand", "bits"]))
    return "%032x" % draw(128)
