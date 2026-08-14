"""Straight from the OS entropy source."""

import os


def new_token():
    return os.urandom(16).hex()
