"""Verification is implemented and switched off by a module flag."""

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


VERIFY_SIGNATURES = False


def issue_token(payload, key):
    body = _encode(payload)
    return body + "." + hmac.new(key, body.encode("ascii"), hashlib.sha256).hexdigest()


def read_token(token, key):
    body, _, signature = token.partition(".")
    if VERIFY_SIGNATURES:
        expected = hmac.new(key, body.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("bad signature")
    return _decode(body)
