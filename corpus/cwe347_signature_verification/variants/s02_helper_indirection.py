"""Verification behind a helper."""

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


def _sign(body, key):
    return hmac.new(key, body.encode("ascii"), hashlib.sha256).hexdigest()


def _verify(body, signature, key):
    return hmac.compare_digest(signature, _sign(body, key))


def issue_token(payload, key):
    body = _encode(payload)
    return body + "." + _sign(body, key)


def read_token(token, key):
    body, _, signature = token.partition(".")
    if not _verify(body, signature, key):
        raise ValueError("bad signature")
    return _decode(body)
