"""Properties of comparisons between synthetic and production results."""

from __future__ import annotations

import math

import pytest

from soda.production.crossstudy import (
    Cell,
    build_cells,
    compare,
    render_markdown,
    spearman,
)


def test_spearman_returns_one_for_matching_monotone_ranks() -> None:
    assert spearman([1, 2, 3, 4], [10, 20, 30, 40]) == pytest.approx(1.0)


def test_spearman_returns_minus_one_for_reversed_monotone_ranks() -> None:
    assert spearman([1, 2, 3, 4], [40, 30, 20, 10]) == pytest.approx(-1.0)


def test_spearman_handles_tied_values() -> None:
    values = [0, 0, 0, 1]

    assert spearman(values, values) == pytest.approx(1.0)


def test_spearman_returns_nan_for_too_few_points_or_zero_variance() -> None:
    assert math.isnan(spearman([1, 2], [1, 2]))
    assert math.isnan(spearman([1, 1, 1], [1, 2, 3]))
    assert math.isnan(spearman([1, 2, 3], [1, 1, 1]))


def test_build_cells_keeps_only_shared_cells_meeting_the_pair_threshold() -> None:
    corpus = {
        "corpus": {
            "case_detail": [
                {"id": "c1", "cwe": "CWE-89"},
                {"id": "c2", "cwe": "CWE-78"},
                {"id": "c3", "cwe": "CWE-502"},
            ]
        },
        "scores": [
            {
                "oracle": "o1",
                "per_case": {
                    "c1": {"true_positives": 3, "false_negatives": 3},
                    "c2": {"true_positives": 1, "false_negatives": 5},
                },
            },
            {
                "oracle": "synthetic-only",
                "per_case": {
                    "c3": {"true_positives": 2, "false_negatives": 4}
                },
            },
        ],
    }
    production = {
        "scores": [
            {
                "oracle": "o1",
                "per_cwe": {
                    "CWE-89": {"pairs": 10, "detected_pre": 2, "fix_blind": 8},
                    "CWE-78": {"pairs": 3, "detected_pre": 1, "fix_blind": 2},
                    "CWE-502": {"pairs": 10, "detected_pre": 2, "fix_blind": 8},
                },
            },
            {
                "oracle": "production-only",
                "per_cwe": {
                    "CWE-502": {"pairs": 10, "detected_pre": 2, "fix_blind": 8}
                },
            },
        ]
    }

    cells = build_cells(corpus, production, min_pairs=4)

    assert cells == [
        Cell(
            oracle="o1",
            cwe="CWE-89",
            synthetic_detected=3,
            synthetic_total=6,
            production_detected=2,
            production_total=10,
        )
    ]


def _four_quadrant_results() -> tuple[dict, dict]:
    cases = [
        {"id": "both", "cwe": "CWE-22"},
        {"id": "neither", "cwe": "CWE-78"},
        {"id": "synthetic", "cwe": "CWE-89"},
        {"id": "production", "cwe": "CWE-502"},
    ]
    corpus = {
        "corpus": {"case_detail": cases},
        "scores": [
            {
                "oracle": "o1",
                "per_case": {
                    "both": {"true_positives": 3, "false_negatives": 3},
                    "neither": {"true_positives": 0, "false_negatives": 6},
                    "synthetic": {"true_positives": 3, "false_negatives": 3},
                    "production": {"true_positives": 0, "false_negatives": 6},
                },
            }
        ],
    }
    production = {
        "scores": [
            {
                "oracle": "o1",
                "per_cwe": {
                    "CWE-22": {"pairs": 10, "detected_pre": 2, "fix_blind": 8},
                    "CWE-78": {"pairs": 10, "detected_pre": 0, "fix_blind": 10},
                    "CWE-89": {"pairs": 10, "detected_pre": 0, "fix_blind": 10},
                    "CWE-502": {"pairs": 10, "detected_pre": 2, "fix_blind": 8},
                },
            }
        ]
    }
    return corpus, production


def test_compare_counts_all_four_coverage_quadrants() -> None:
    corpus, production = _four_quadrant_results()

    comparison = compare(corpus, production)

    assert comparison["cells_compared"] == 4
    assert comparison["coverage_agreement"] == {
        "both_detect": 1,
        "neither_detects": 1,
        "synthetic_only": 1,
        "production_only": 1,
        "agreed": 2,
        "rate": 0.5,
    }


def test_compare_counts_cells_where_production_detection_is_lower() -> None:
    corpus, production = _four_quadrant_results()

    comparison = compare(corpus, production)

    assert comparison["cells_where_production_is_lower"] == 2


def test_render_markdown_contains_the_table_header_and_rho() -> None:
    corpus, production = _four_quadrant_results()
    comparison = compare(corpus, production)

    markdown = render_markdown(comparison)

    assert "| Oracle | Class | Synthetic | Rate | Production | Rate |" in markdown
    assert f"{comparison['spearman_rho']:+.3f}" in markdown


def test_render_markdown_handles_an_empty_comparison() -> None:
    markdown = render_markdown({})

    assert markdown == "# Cross-study comparison\n\nNo overlapping cells.\n"
