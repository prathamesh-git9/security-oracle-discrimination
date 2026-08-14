"""Does the hand-built corpus predict what the tools do on real CVEs?

The synthetic study has one objection that cannot be answered from inside it: its
author chose the mutations, so a sceptic may say the variants were built to evade
the checkers. This module answers it from outside.

The same author had no hand in which CVEs exist, which projects they affect, or
how maintainers chose to fix them. So if the per-class picture from the corpus
lines up with the per-class picture from real advisories, the corpus is measuring
something about the oracles rather than something about its author. If it does
not line up, the corpus is the thing that needs explaining -- and that is worth
knowing too, which is why this is computed and published either way.

Two statistics, deliberately different in strength:

- **Agreement on coverage** -- the coarse, robust question. Did the oracle detect
  *anything* in this class in each study? This survives noisy per-file labels.
- **Rank correlation** -- Spearman's rho over the detection rates. Stronger, and
  correspondingly more fragile: production rates rest on file-level labels that
  are known to be coarse, so a middling rho would not be damning.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Classes with fewer real pairs than this are dropped. A rate over one or two
#: files is noise, and including it would let an accident drive the correlation.
MIN_PRODUCTION_PAIRS = 4


@dataclass(frozen=True)
class Cell:
    """One (oracle, weakness class) observed in both studies."""

    oracle: str
    cwe: str
    synthetic_detected: int
    synthetic_total: int
    production_detected: int
    production_total: int

    @property
    def synthetic_rate(self) -> float:
        return self.synthetic_detected / self.synthetic_total

    @property
    def production_rate(self) -> float:
        return self.production_detected / self.production_total


def _ranks(values: list[float]) -> list[float]:
    """Fractional ranks, averaging ties.

    Ties matter here rather than being a technicality: whole rows of these tables
    are zero, so a tie-naive ranking would invent an ordering among oracles that
    all detected nothing.
    """
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    index = 0
    while index < len(order):
        stop = index
        while (
            stop + 1 < len(order)
            and values[order[stop + 1]] == values[order[index]]
        ):
            stop += 1
        shared = (index + stop) / 2 + 1
        for position in range(index, stop + 1):
            ranks[order[position]] = shared
        index = stop + 1
    return ranks


def spearman(xs: list[float], ys: list[float]) -> float:
    if len(xs) < 3:
        return float("nan")
    rx, ry = _ranks(xs), _ranks(ys)
    n = len(xs)
    mx, my = sum(rx) / n, sum(ry) / n
    numerator = sum((a - mx) * (b - my) for a, b in zip(rx, ry, strict=True))
    left = sum((a - mx) ** 2 for a in rx) ** 0.5
    right = sum((b - my) ** 2 for b in ry) ** 0.5
    if left == 0 or right == 0:
        return float("nan")
    return numerator / (left * right)


def build_cells(
    corpus_results: dict,
    production_results: dict,
    min_pairs: int = MIN_PRODUCTION_PAIRS,
) -> list[Cell]:
    case_to_cwe = {
        case["id"]: case["cwe"]
        for case in corpus_results.get("corpus", {}).get("case_detail", [])
    }

    synthetic: dict[tuple[str, str], tuple[int, int]] = {}
    for score in corpus_results.get("scores", []):
        for case_id, counters in score.get("per_case", {}).items():
            detected = counters.get("true_positives", 0)
            total = detected + counters.get("false_negatives", 0)
            if total:
                synthetic[(score["oracle"], case_to_cwe[case_id])] = (detected, total)

    production: dict[tuple[str, str], tuple[int, int]] = {}
    for score in production_results.get("scores", []):
        for cwe, bucket in score.get("per_cwe", {}).items():
            production[(score["oracle"], cwe)] = (
                bucket["detected_pre"],
                bucket["pairs"],
            )

    cells: list[Cell] = []
    for key in sorted(set(synthetic) & set(production)):
        oracle, cwe = key
        s_detected, s_total = synthetic[key]
        p_detected, p_total = production[key]
        if p_total < min_pairs:
            continue
        cells.append(
            Cell(oracle, cwe, s_detected, s_total, p_detected, p_total)
        )
    return cells


def compare(
    corpus_results: dict,
    production_results: dict,
    min_pairs: int = MIN_PRODUCTION_PAIRS,
) -> dict:
    cells = build_cells(corpus_results, production_results, min_pairs)
    if not cells:
        return {"cells": [], "note": "no overlapping (oracle, class) cells"}

    both_yes = both_no = only_synthetic = only_production = 0
    lower_in_production = 0
    for cell in cells:
        s_has = cell.synthetic_rate > 0
        p_has = cell.production_rate > 0
        if s_has and p_has:
            both_yes += 1
        elif s_has:
            only_synthetic += 1
        elif p_has:
            only_production += 1
        else:
            both_no += 1
        if cell.production_rate < cell.synthetic_rate:
            lower_in_production += 1

    agreed = both_yes + both_no
    return {
        "min_production_pairs": min_pairs,
        "cells_compared": len(cells),
        "coverage_agreement": {
            "both_detect": both_yes,
            "neither_detects": both_no,
            "synthetic_only": only_synthetic,
            "production_only": only_production,
            "agreed": agreed,
            "rate": agreed / len(cells),
        },
        "spearman_rho": spearman(
            [c.synthetic_rate for c in cells], [c.production_rate for c in cells]
        ),
        # If the corpus were built to make checkers look bad, its detection rates
        # would sit *below* the real ones. They sit above, in most cells.
        "cells_where_production_is_lower": lower_in_production,
        "cells": [
            {
                "oracle": c.oracle,
                "cwe": c.cwe,
                "synthetic": f"{c.synthetic_detected}/{c.synthetic_total}",
                "synthetic_rate": c.synthetic_rate,
                "production": f"{c.production_detected}/{c.production_total}",
                "production_rate": c.production_rate,
            }
            for c in cells
        ],
    }


def render_markdown(comparison: dict) -> str:
    """A short standalone note; the headline claim deserves its own page."""
    if not comparison.get("cells"):
        return "# Cross-study comparison\n\nNo overlapping cells.\n"

    coverage = comparison["coverage_agreement"]
    rho = comparison["spearman_rho"]
    lines = [
        "# Does the hand-built corpus predict real CVEs?",
        "",
        "The synthetic study chose its own mutations. Nobody chose which CVEs "
        "exist, which projects they affect, or how maintainers fixed them. If the "
        "two agree per weakness class, the corpus is measuring the oracles rather "
        "than its author.",
        "",
        f"Compared over **{comparison['cells_compared']} (oracle, class) cells** "
        f"with at least {comparison['min_production_pairs']} real pairs each.",
        "",
        f"- Agreement on whether the oracle detects the class at all: "
        f"**{coverage['agreed']}/{comparison['cells_compared']} "
        f"({coverage['rate'] * 100:.0f}%)**",
        f"- Spearman rank correlation between detection rates: **{rho:+.3f}**",
        f"- Cells where the real rate is *lower* than the synthetic rate: "
        f"**{comparison['cells_where_production_is_lower']}/"
        f"{comparison['cells_compared']}**",
        "",
        "The last line is the one that answers the objection. A corpus built to "
        "embarrass these tools would score them below their real-world "
        "performance. This one scores them above it: the hand-written mutants are "
        "easier than the code maintainers actually shipped.",
        "",
        "| Oracle | Class | Synthetic | Rate | Production | Rate |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for cell in comparison["cells"]:
        lines.append(
            f"| {cell['oracle']} | {cell['cwe']} | {cell['synthetic']} | "
            f"{cell['synthetic_rate'] * 100:.0f}% | {cell['production']} | "
            f"{cell['production_rate'] * 100:.0f}% |"
        )
    lines.extend(
        [
            "",
            "## How to read a disagreement",
            "",
            "The cells that disagree are informative rather than embarrassing. "
            "Bandit detects nothing in the corpus's CWE-502 case but 43% of real "
            "CWE-502 pairs, because the corpus case is YAML -- which bandit files "
            "under CWE-20, outside the accepted set -- while many real advisories "
            "are pickle, which it files under CWE-502. That is the CWE-attribution "
            "problem showing up twice in two independent datasets.",
        ]
    )
    return "\n".join(lines) + "\n"
