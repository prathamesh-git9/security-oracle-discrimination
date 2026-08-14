"""Render audit evidence as a compact, inspectable Markdown report.

The report keeps execution-established labels beside oracle judgements so that
coverage gaps, form sensitivity and false alarms remain visibly distinct.
"""

from __future__ import annotations

import math

__all__ = ["render_markdown"]


def _finite(value: object) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _percentage(value: object) -> str:
    number = _finite(value)
    return "n/a" if number is None else f"{number * 100:.1f}%"


def _signed(value: object) -> str:
    number = _finite(value)
    return "n/a" if number is None else f"{number:+.3f}"


def _interval(interval: object, *, percentage: bool) -> str:
    if not isinstance(interval, (list, tuple)) or len(interval) != 2:
        return ""
    low = _finite(interval[0])
    high = _finite(interval[1])
    if percentage:
        low_text = "n/a" if low is None else f"{low * 100:.1f}"
        high_text = "n/a" if high is None else f"{high * 100:.1f}"
    else:
        low_text = "n/a" if low is None else f"{low:+.3f}"
        high_text = "n/a" if high is None else f"{high:+.3f}"
    return f" [{low_text}, {high_text}]"


def _statistic(
    score: dict,
    intervals: dict,
    statistic: str,
    *,
    percentage: bool,
) -> str:
    formatter = _percentage if percentage else _signed
    rendered = formatter(score.get(statistic))
    oracle_intervals = intervals.get(str(score.get("oracle", "")), {})
    if not isinstance(oracle_intervals, dict) or statistic not in oracle_intervals:
        return rendered
    return rendered + _interval(
        oracle_intervals[statistic],
        percentage=percentage,
    )


def _cell(value: object) -> str:
    text = str(value) if value not in (None, "") else "n/a"
    return text.replace("|", "\\|").replace("\r\n", "<br>").replace("\n", "<br>")


def _table(headers: list[str], rows: list[list[object]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |"]
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    lines.extend("| " + " | ".join(_cell(value) for value in row) + " |" for row in rows)
    return lines


def _score_order(score: dict) -> tuple[bool, float, str]:
    value = _finite(score.get("youden_j"))
    return (
        value is None,
        -(value if value is not None else 0.0),
        str(score.get("oracle", "")),
    )


def _count(score: dict, key: str) -> int:
    value = score.get(key, 0)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _fraction(score: dict, numerator: str, denominator: str) -> str:
    return f"{_count(score, numerator)}/{_count(score, denominator)}"


def _provenance(results: dict) -> str:
    environment = results.get("environment", {})
    corpus = results.get("corpus", {})
    labels = corpus.get("labels", {})
    digest = str(environment.get("corpus_sha256", ""))[:16] or "n/a"
    label_text = ", ".join(
        f"{label} {labels.get(label, 0)}"
        for label in ("secure", "vulnerable", "invalid")
    )
    return (
        f"Generated: {results.get('generated_at', 'n/a')}; "
        f"Python: {environment.get('python', 'n/a')}; "
        f"platform: {environment.get('platform', 'n/a')}; "
        f"corpus SHA-256: {digest}; "
        f"corpus: {corpus.get('cases', 0)} cases / "
        f"{corpus.get('variants', 0)} variants / {label_text}."
    )


def _headline(scores: list[dict]) -> str:
    candidates = [
        score
        for score in scores
        if _finite(score.get("stealth_escape_rate")) is not None
    ]
    if not candidates:
        return (
            "No oracle had behaviourally identical vulnerable variants eligible "
            "for the form-sensitivity measure."
        )
    worst = max(
        candidates,
        key=lambda score: (
            _finite(score.get("stealth_escape_rate")) or 0.0,
            _count(score, "stealth_escaped"),
        ),
    )
    oracle = _cell(worst.get("oracle", "n/a"))
    escaped = _count(worst, "stealth_escaped")
    total = _count(worst, "stealth_total")
    return (
        f"For {oracle}, the worst result, {escaped} of {total} behaviourally "
        "identical vulnerable variants escaped even though the checker provably "
        "had a rule for the weakness."
    )


def _per_case_sections(cases: list[dict], scores: list[dict]) -> list[str]:
    lines: list[str] = []
    for case in cases:
        case_id = str(case.get("id", ""))
        heading = ": ".join(
            part
            for part in (
                case_id,
                str(case.get("cwe", "")),
                str(case.get("title", "")),
            )
            if part
        )
        lines.extend([f"### {heading or 'Unknown case'}", ""])
        rows: list[list[object]] = []
        for score in scores:
            all_cases = score.get("per_case", {})
            counters = all_cases.get(case_id, {}) if isinstance(all_cases, dict) else {}
            rows.append(
                [
                    score.get("oracle", "n/a"),
                    counters.get("true_positives", 0),
                    counters.get("false_negatives", 0),
                    counters.get("true_negatives", 0),
                    counters.get("false_positives", 0),
                    (
                        f"{counters.get('stealth_escaped', 0)}/"
                        f"{counters.get('stealth_total', 0)}"
                    ),
                ]
            )
        lines.extend(
            _table(
                ["Oracle", "TP", "FN", "TN", "FP", "Stealth escaped/total"],
                rows,
            )
        )
        lines.append("")
    return lines


def _disagreements(records: list[dict]) -> tuple[list[list[object]], int]:
    rows: list[list[object]] = []
    for record in records:
        label = record.get("label")
        if label not in {"secure", "vulnerable"}:
            continue
        expected = label == "vulnerable"
        verdicts = record.get("verdicts", {})
        if not isinstance(verdicts, dict):
            verdicts = {}
        present = {
            str(oracle): verdict
            for oracle, verdict in verdicts.items()
            if isinstance(verdict, dict) and "flagged_target" in verdict
        }
        disagrees = any(
            bool(verdict["flagged_target"]) != expected
            for verdict in present.values()
        )
        if not disagrees:
            continue
        flagged = sorted(
            oracle
            for oracle, verdict in present.items()
            if bool(verdict["flagged_target"])
        )
        not_flagged = sorted(
            oracle
            for oracle, verdict in present.items()
            if not bool(verdict["flagged_target"])
        )
        rows.append(
            [
                record.get("case_id", "n/a"),
                record.get("variant_id", "n/a"),
                label,
                ", ".join(flagged) or "none",
                ", ".join(not_flagged) or "none",
            ]
        )
    return rows[:40], max(0, len(rows) - 40)


def render_markdown(results: dict) -> str:
    """Expose where oracle judgements diverge from behaviour, without rerunning it."""
    corpus = results.get("corpus", {})
    cases = corpus.get("case_detail", [])
    intervals = results.get("confidence_intervals", {})
    if not isinstance(intervals, dict):
        intervals = {}
    raw_scores = results.get("scores", [])
    scores = sorted(
        (score for score in raw_scores if isinstance(score, dict)),
        key=_score_order,
    )

    lines = [
        "# Security oracle discrimination audit",
        "",
        _provenance(results),
        "",
        "## Corpus",
        "",
    ]
    corpus_rows = [
        [
            case.get("cwe", "n/a"),
            case.get("title", "n/a"),
            case.get("variants", 0),
            ", ".join(str(cwe) for cwe in case.get("accept_cwes", [])) or "none",
            case.get("witness", "n/a"),
        ]
        for case in cases
        if isinstance(case, dict)
    ]
    lines.extend(
        _table(
            ["CWE", "Title", "Variants", "Accepted CWEs", "Witness"],
            corpus_rows,
        )
    )

    score_rows = [
        [
            score.get("oracle", "n/a"),
            score.get("version", "n/a"),
            _statistic(score, intervals, "sensitivity", percentage=True),
            _statistic(score, intervals, "specificity", percentage=True),
            _statistic(score, intervals, "youden_j", percentage=False),
        ]
        for score in scores
    ]
    lines.extend(["", "## Oracle scores", ""])
    lines.extend(
        _table(
            ["Oracle", "Version", "Sensitivity", "Specificity", "Youden J"],
            score_rows,
        )
    )

    form_rows = [
        [
            score.get("oracle", "n/a"),
            _fraction(score, "cases_with_rule", "cases_total"),
            _count(score, "stealth_total"),
            _count(score, "stealth_escaped"),
            _statistic(score, intervals, "stealth_escape_rate", percentage=True),
        ]
        for score in scores
    ]
    lines.extend(["", "## Form sensitivity", ""])
    lines.extend(
        _table(
            [
                "Oracle",
                "Cases with rule",
                "Stealth variants",
                "Escaped",
                "Stealth escape rate",
            ],
            form_rows,
        )
    )
    lines.extend(["", _headline(scores)])

    alarm_rows = []
    for score in scores:
        decoy_rate = _statistic(
            score,
            intervals,
            "decoy_alarm_rate",
            percentage=True,
        )
        plain_rate = _percentage(score.get("plain_secure_alarm_rate"))
        alarm_rows.append(
            [
                score.get("oracle", "n/a"),
                f"{_fraction(score, 'decoy_flagged', 'decoy_total')} ({decoy_rate})",
                (
                    f"{_fraction(score, 'plain_secure_flagged', 'plain_secure_total')} "
                    f"({plain_rate})"
                ),
            ]
        )
    lines.extend(["", "## False alarms on secure code", ""])
    lines.extend(
        _table(
            ["Oracle", "Decoy variants flagged", "Plain secure variants flagged"],
            alarm_rows,
        )
    )

    lines.extend(["", "## Per-case detail", ""])
    lines.extend(_per_case_sections(cases, scores))

    records = results.get("records", [])
    records = records if isinstance(records, list) else []
    disagreement_rows, omitted = _disagreements(records)
    lines.extend(["## Disagreements worth reading", ""])
    lines.extend(
        _table(
            ["Case", "Variant", "Label", "Flagged by", "Not flagged by"],
            disagreement_rows,
        )
    )
    if omitted:
        lines.extend(["", f"{omitted} additional disagreements omitted."])

    oracle_data = results.get("oracles", {})
    errors = oracle_data.get("errors", {}) if isinstance(oracle_data, dict) else {}
    if isinstance(errors, dict) and errors:
        lines.extend(["", "## Oracle failures", ""])
        for oracle, error in sorted(errors.items()):
            lines.append(f"- {_cell(oracle)}: {_cell(error)}")

    return "\n".join(lines).rstrip() + "\n"
