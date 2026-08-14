"""Verified, but with == instead of a constant-time comparison.

This leaks timing. It does not let the attacker forge a token with the material
in the witness, so the behavioural label and the lint verdict come apart here for
a real reason rather than a lexical one.
"""

import base64
import hashlib
import hmac
import json


def _encode(payload):
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode(body):
    padded = body + "=" * (-len(body) % 4)
    return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))


def issue_token(payload, key):
    body = _encode(payload)
    signature = hmac.new(key, body.encode("ascii"), hashlib.sha256).hexdigest()
    return body + "." + signature


def read_token(token, key):
    body, _, signature = token.partition(".")
    expected = hmac.new(key, body.encode("ascii"), hashlib.sha256).hexdigest()
    if signature != expected:
        raise ValueError("bad signature")
    return _decode(body)
