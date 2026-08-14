"""The pre-declared map from a weakness class to the identifiers that count.

These are the same sets recorded in each `corpus/*/case.json` before any oracle
was run. They live here as well because the production study scores real CVEs
against the same rule, and the two studies are only comparable if the rule is
literally the same object. `tests/test_cwe_table.py` asserts the two agree, so a
drift between them fails the build rather than quietly changing what "detected"
means in one half of the project.

Tools label the same weakness with neighbouring identifiers -- a cheap password
digest is CWE-916 to one and CWE-327 to another -- so scoring on an exact string
would measure taxonomy agreement rather than detection.
"""

from __future__ import annotations

ACCEPTED_CWES: dict[str, tuple[str, ...]] = {
    "CWE-22": ("CWE-22", "CWE-23", "CWE-36", "CWE-73"),
    "CWE-78": ("CWE-78", "CWE-77", "CWE-88"),
    "CWE-89": ("CWE-89", "CWE-943"),
    "CWE-330": ("CWE-330", "CWE-338", "CWE-335"),
    "CWE-347": ("CWE-347", "CWE-345", "CWE-287", "CWE-807"),
    "CWE-502": ("CWE-502",),
    "CWE-916": ("CWE-916", "CWE-327", "CWE-328", "CWE-326", "CWE-759", "CWE-760"),
}

#: The weakness classes this project has an opinion about. An advisory outside
#: this set is not evidence about these oracles, so it is not collected.
COVERED = tuple(ACCEPTED_CWES)


def accepted_for(cwes: list[str] | tuple[str, ...]) -> frozenset[str]:
    """Identifiers counting as detection for an advisory tagged with ``cwes``.

    An advisory often carries more than one class -- unsafe deserialisation is
    routinely filed as both CWE-502 and CWE-94. The union is taken because the
    question asked of the oracle is "did you report *this weakness*", and any of
    the advisory's own classes is a fair answer to that.
    """
    accepted: set[str] = set()
    for cwe in cwes:
        accepted.update(ACCEPTED_CWES.get(cwe, ()))
    return frozenset(accepted)


def covered_cwes(cwes: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    """The subset of an advisory's classes that this project covers."""
    return tuple(cwe for cwe in cwes if cwe in ACCEPTED_CWES)
