"""Drawn from the random module -- but from its OS-backed generator.

The module name that most rules key on is present; the predictability is not.
"""

import random

_RNG = random.SystemRandom()


def new_token():
    return "%032x" % _RNG.getrandbits(128)
