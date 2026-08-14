"""Correct, with the vulnerable form quoted in a comment."""

import secrets


def new_token():
    # Never seed a token generator from the clock, i.e. never write
    #   random.seed(int(time.time())); return "%032x" % random.getrandbits(128)
    # because the seed space is then small enough to search exhaustively.
    return secrets.token_hex(16)
