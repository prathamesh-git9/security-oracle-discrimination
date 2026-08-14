"""Behavioural distinctions between the built-in oracle families."""

from __future__ import annotations

from pathlib import Path

import pytest

from soda.oracles.base import normalise_cwes
from soda.oracles.pattern import PatternOracle
from soda.oracles.structural import StructuralOracle


def test_pattern_and_structural_oracles_are_always_available() -> None:
    assert PatternOracle().available() is True
    assert StructuralOracle().available() is True


@pytest.mark.parametrize("oracle", [PatternOracle(), StructuralOracle()])
def test_built_in_oracles_find_cwe_89_in_the_canonical_sql_variant(
    oracle: PatternOracle | StructuralOracle,
    corpus_root: Path,
) -> None:
    path = corpus_root / "cwe089_sql_injection" / "variants" / "v01_fstring.py"

    findings = oracle.scan([path]).get(path, [])

    assert findings
    assert any("CWE-89" in finding.cwes for finding in findings)


def test_pattern_oracle_flags_a_comment_that_structural_ignores(
    corpus_root: Path,
) -> None:
    path = (
        corpus_root
        / "cwe089_sql_injection"
        / "variants"
        / "s04_comment_decoy.py"
    )

    pattern_findings = PatternOracle().scan([path]).get(path, [])
    structural_findings = StructuralOracle().scan([path]).get(path, [])

    assert pattern_findings
    assert structural_findings == []


@pytest.mark.parametrize(
    "reported",
    [
        {"id": 78, "link": "https://example.invalid/CWE-78"},
        ["CWE-78: Improper Neutralization ..."],
        "cwe-78",
    ],
)
def test_normalise_cwes_extracts_cwe_78_from_real_tool_shapes(reported: object) -> None:
    assert normalise_cwes(reported) == ("CWE-78",)


def test_normalise_cwes_returns_empty_tuple_for_none() -> None:
    assert normalise_cwes(None) == ()


def test_structural_oracle_reports_a_parse_error_instead_of_raising(
    tmp_path: Path,
) -> None:
    path = tmp_path / "broken.py"
    path.write_text("def broken(:\n    pass\n", encoding="utf-8")

    findings = StructuralOracle().scan([path])[path]

    assert any(finding.rule_id == "AST-PARSE-ERROR" for finding in findings)
