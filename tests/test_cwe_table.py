"""The two studies must score detection by the same rule.

`corpus/*/case.json` records the accepted CWE sets that were fixed before any
oracle ran; `soda.cwe` holds the same table for the production study. If they
drift, the word "detected" quietly means two different things in the two halves
of the project and the results stop being comparable. That is worth a build
failure rather than a footnote.
"""

from __future__ import annotations

import json
import re

from soda.corpus import load_corpus
from soda.cwe import ACCEPTED_CWES, accepted_for, covered_cwes

CWE_ID = re.compile(r"^CWE-\d+$")


def test_every_corpus_case_matches_the_shared_table(corpus_root):
    for case in load_corpus(corpus_root):
        assert case.cwe in ACCEPTED_CWES, f"{case.case_id}: {case.cwe} missing from table"
        assert set(case.accept_cwes) == set(ACCEPTED_CWES[case.cwe]), (
            f"{case.case_id}: accepted set drifted from soda.cwe"
        )


def test_manifests_on_disk_agree_with_the_shared_table(corpus_root):
    for manifest_path in sorted(corpus_root.glob("*/case.json")):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert set(manifest["accept_cwes"]) == set(ACCEPTED_CWES[manifest["cwe"]])


def test_table_entries_are_well_formed_and_self_inclusive():
    for cwe, accepted in ACCEPTED_CWES.items():
        assert CWE_ID.match(cwe), f"{cwe} is not a CWE identifier"
        assert cwe in accepted, f"{cwe} must accept itself"
        assert all(CWE_ID.match(entry) for entry in accepted), cwe
        assert len(set(accepted)) == len(accepted), f"{cwe} has duplicates"


def test_accepted_for_takes_the_union_across_an_advisorys_classes():
    both = accepted_for(["CWE-89", "CWE-78"])
    assert {"CWE-89", "CWE-943"} <= both
    assert {"CWE-78", "CWE-77", "CWE-88"} <= both


def test_unknown_classes_contribute_nothing_rather_than_raising():
    assert accepted_for(["CWE-1004"]) == frozenset()
    assert accepted_for([]) == frozenset()
    assert covered_cwes(["CWE-94", "CWE-502"]) == ("CWE-502",)
