"""The obvious correct answer."""

import secrets


def new_token():
    return secrets.token_hex(16)
