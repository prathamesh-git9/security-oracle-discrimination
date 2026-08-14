"""Textbook predictable form: a Mersenne Twister seeded from the clock."""

import random
import time

_RNG = random.Random(int(time.time()))


def new_token():
    return "%032x" % _RNG.getrandbits(128)
