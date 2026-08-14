"""Unverified, behind a helper that only decodes."""

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


def _payload_of(token):
    body, _, _signature = token.partition(".")
    return _decode(body)


def issue_token(payload, key):
    body = _encode(payload)
    return body + "." + hmac.new(key, body.encode("ascii"), hashlib.sha256).hexdigest()


def read_token(token, key):
    return _payload_of(token)
