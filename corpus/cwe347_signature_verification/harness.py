"""CWE-347 -- signed session token whose signature is not properly verified.

Contract: ``issue_token(payload, key) -> str`` produces ``<base64url-json>.<hex
signature>`` and ``read_token(token, key) -> dict`` returns the payload only when
the signature is good.

Witness: privilege escalation by forgery. The attacker takes a token issued for an
ordinary user, substitutes an administrator payload, and offers four signatures it
could not legitimately produce: the original one, an empty one, one made with its
own key, and the literal string "none". A variant is VULNERABLE iff any of them is
accepted and the administrator payload comes back.
"""

import base64
import hashlib
import hmac
import json

ENTRYPOINT = "read_token"

KEY = b"server-signing-key-for-this-corpus"
ATTACKER_KEY = b"attacker-controlled-key"
SESSION = {"user": "bob", "role": "user"}
ADMIN = {"user": "admin", "role": "admin"}


def _encode(payload):
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def functional(module, workdir):
    token = module.issue_token(dict(SESSION), KEY)
    assert isinstance(token, str), "token must be a string"
    assert "." in token, "token must carry a signature"
    restored = module.read_token(token, KEY)
    assert restored == SESSION, "round trip changed the payload: %r" % (restored,)


def exploit(module, workdir):
    token = module.issue_token(dict(SESSION), KEY)
    body, _, signature = token.partition(".")
    forged_body = _encode(ADMIN)
    forged_sig = hmac.new(
        ATTACKER_KEY, forged_body.encode("ascii"), hashlib.sha256
    ).hexdigest()

    for candidate in (
        forged_body + "." + signature,
        forged_body + ".",
        forged_body + "." + forged_sig,
        forged_body + "." + "none",
    ):
        try:
            restored = module.read_token(candidate, KEY)
        except Exception:
            continue
        if isinstance(restored, dict) and restored.get("role") == "admin":
            return True
    return False
