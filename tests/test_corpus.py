"""Checks for the declared corpus structure and source validity."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from soda.audit import corpus_integrity
from soda.corpus import load_corpus


def test_every_case_loads_and_the_corpus_has_at_least_eight_cases(
    corpus_root: Path,
) -> None:
    cases = load_corpus(corpus_root)

    assert len(cases) >= 8


def test_every_case_has_one_vulnerable_canonical_variant(
    corpus_root: Path,
) -> None:
    for case in load_corpus(corpus_root):
        canonical = [variant for variant in case.variants if variant.canonical]

        assert len(canonical) == 1, case.case_id
        assert canonical[0].declared == "vulnerable", case.case_id


def test_every_case_has_secure_and_vulnerable_variants(corpus_root: Path) -> None:
    for case in load_corpus(corpus_root):
        declared = {variant.declared for variant in case.variants}

        assert "secure" in declared, case.case_id
        assert "vulnerable" in declared, case.case_id


def test_every_manifest_variant_exists_and_parses_as_python(
    corpus_root: Path,
) -> None:
    for case in load_corpus(corpus_root):
        for variant in case.variants:
            assert variant.path.is_file(), variant.path
            source = variant.path.read_text(encoding="utf-8")
            ast.parse(source, filename=str(variant.path))


def test_every_case_declares_only_well_formed_accepted_cwes(
    corpus_root: Path,
) -> None:
    cwe_pattern = re.compile(r"^CWE-\d+$")

    for case in load_corpus(corpus_root):
        assert case.accept_cwes, case.case_id
        assert all(cwe_pattern.fullmatch(cwe) for cwe in case.accept_cwes), (
            case.case_id,
            case.accept_cwes,
        )


def test_variant_ids_are_unique_within_each_case(corpus_root: Path) -> None:
    for case in load_corpus(corpus_root):
        variant_ids = [variant.variant_id for variant in case.variants]

        assert len(variant_ids) == len(set(variant_ids)), case.case_id


def test_corpus_integrity_reports_no_problems(corpus_root: Path) -> None:
    assert corpus_integrity(corpus_root) == []
