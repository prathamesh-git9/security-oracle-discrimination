"""Execution-backed ground-truth checks for the fast SQL case."""

from __future__ import annotations

from pathlib import Path

import pytest

from soda.corpus import load_case
from soda.groundtruth import evaluate
from soda.models import GroundTruth, Label, Variant


def test_every_sql_variant_earns_its_declared_label(corpus_root: Path) -> None:
    case = load_case(corpus_root / "cwe089_sql_injection")

    for variant in case.variants:
        truth = evaluate(case, variant)

        assert truth.functional_ok is True, variant.variant_id
        assert truth.label.value == variant.declared, variant.variant_id


@pytest.mark.parametrize(
    ("functional_ok", "exploited", "expected"),
    [
        (False, False, Label.INVALID),
        (False, True, Label.INVALID),
        (True, True, Label.VULNERABLE),
        (True, False, Label.SECURE),
    ],
)
def test_label_for_maps_functional_and_exploit_results(
    functional_ok: bool,
    exploited: bool,
    expected: Label,
) -> None:
    assert GroundTruth.label_for(functional_ok, exploited) is expected


def test_variant_with_a_broken_functional_contract_is_invalid(
    corpus_root: Path,
    tmp_path: Path,
) -> None:
    case = load_case(corpus_root / "cwe089_sql_injection")
    path = tmp_path / "always_missing.py"
    path.write_text(
        "def lookup_user(conn, username):\n    return None\n",
        encoding="utf-8",
    )
    variant = Variant(
        case_id=case.case_id,
        variant_id="always_missing",
        path=path,
        declared="secure",
    )

    truth = evaluate(case, variant)

    assert truth.functional_ok is False
    assert truth.label is Label.INVALID
