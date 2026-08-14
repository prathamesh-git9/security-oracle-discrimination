"""Predictable, assembled character by character."""

import random
import time

HEX = "0123456789abcdef"
_RNG = random.Random(int(time.time()))


def new_token():
    return "".join(_RNG.choice(HEX) for _ in range(32))
