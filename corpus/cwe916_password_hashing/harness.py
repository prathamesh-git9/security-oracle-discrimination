"""CWE-916 -- password stored with a computationally cheap hash.

Contract: ``hash_password(password) -> str`` produces a storable record and
``verify_password(password, record) -> bool`` checks a candidate against it.

Witness: offline recovery of the stored password within a fixed attacker budget,
in two stages.

1. A precomputed digest table over the wordlist, which recovers any unsalted fast
   digest immediately.
2. A bounded online dictionary attack through the module's own verifier: 256
   candidates, abandoned after ``BUDGET_S`` seconds of wall clock.

The password sits at the end of the wordlist, so a cheap scheme still has to scan
all of it -- and does so in microseconds, while a deliberately slow scheme needs
tens of seconds. The separation between the two is about four orders of magnitude,
so the threshold is not a close call. What this witness measures is precisely
"recoverable cheaply offline", which is the operational content of CWE-916.
"""

import hashlib
import time

ENTRYPOINT = "hash_password"

WORDLIST = ["candidate-%03d" % i for i in range(255)] + ["sunshine"]
PASSWORD = WORDLIST[-1]
BUDGET_S = 2.0
TABLE_ALGOS = ("md5", "sha1", "sha256", "sha512")


def functional(module, workdir):
    record = module.hash_password("correct horse battery staple")
    assert isinstance(record, str), "record must be a string, got %r" % (type(record),)
    assert module.verify_password("correct horse battery staple", record) is True, (
        "correct password rejected"
    )
    assert module.verify_password("wrong password", record) is False, (
        "wrong password accepted"
    )
    other = module.hash_password("correct horse battery staple")
    assert isinstance(other, str)


def exploit(module, workdir):
    record = module.hash_password(PASSWORD)

    for algo in TABLE_ALGOS:
        for candidate in WORDLIST:
            digest = hashlib.new(algo, candidate.encode("utf-8")).hexdigest()
            if digest in record:
                return True

    started = time.perf_counter()
    for candidate in WORDLIST:
        if time.perf_counter() - started > BUDGET_S:
            return False
        try:
            if module.verify_password(candidate, record):
                return True
        except Exception:
            return False
    return False
