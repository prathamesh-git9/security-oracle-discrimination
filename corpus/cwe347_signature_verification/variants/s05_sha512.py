"""Verified with SHA-512."""

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
    signature = hmac.new(key, body.encode("ascii"), hashlib.sha512).hexdigest()
    return body + "." + signature


def read_token(token, key):
    body, _, signature = token.partition(".")
    expected = hmac.new(key, body.encode("ascii"), hashlib.sha512).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("bad signature")
    return _decode(body)
