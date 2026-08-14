"""CWE-330 -- session token drawn from a predictable generator.

Contract: ``new_token() -> str`` returns a fresh 32-character hexadecimal token.

Witness: prediction. The attacker observes one token, searches a small window of
plausible time-derived seeds, replays the two generator idioms the corpus uses,
and -- on a match -- predicts the *next* token before asking for it. A variant is
VULNERABLE iff the prediction is correct.
"""

import random
import time

ENTRYPOINT = "new_token"

HEX = "0123456789abcdef"
SEED_WINDOW = 5


def functional(module, workdir):
    first = module.new_token()
    second = module.new_token()
    assert isinstance(first, str), "token must be a string"
    assert len(first) == 32, "expected 32 characters, got %d" % len(first)
    assert all(ch in HEX for ch in first.lower()), "token is not hexadecimal: %r" % first
    assert first != second, "generator returned the same token twice"


def _replay_getrandbits(rng):
    return "%032x" % rng.getrandbits(128)


def _replay_choice(rng):
    return "".join(rng.choice(HEX) for _ in range(32))


def exploit(module, workdir):
    observed = module.new_token()
    now = int(time.time())
    for seed in range(now - SEED_WINDOW, now + 2):
        for replay in (_replay_getrandbits, _replay_choice):
            rng = random.Random(seed)
            if replay(rng) == observed:
                predicted = replay(rng)
                return predicted == module.new_token()
    return False
