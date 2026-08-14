"""Correct, behind a helper."""

import secrets


def _draw(n_bytes):
    return secrets.token_bytes(n_bytes)


def new_token():
    return _draw(16).hex()
