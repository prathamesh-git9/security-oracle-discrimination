"""Textbook form: the signature is produced but never checked."""

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
    body, _, _signature = token.partition(".")
    return _decode(body)
