"""Tokens from secrets; the random module used for retry jitter.

Jitter is a legitimate use of a fast, predictable generator. The weakness is in
what the numbers are used for, not in which module produced them.
"""

import random
import secrets


def backoff_jitter(attempt):
    return random.random() * min(2**attempt, 30)


def new_token():
    return secrets.token_hex(16)
