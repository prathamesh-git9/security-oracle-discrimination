"""A regular-expression oracle: the "grep for the dangerous call" family.

This is a *reconstruction*, not a copy of any particular published harness. It
exists because a substantial share of security checks in circulation -- in
benchmark scoring scripts, in CI gates, in review checklists -- are ultimately
string matches over source text, and that family deserves a representative in the
comparison. The rules below are written in good faith: they are what a competent
engineer produces in an afternoon, and they name the same sinks the real tools do.

The one property that matters for this study is that a regular expression cannot
see a program. It sees characters, so it cannot distinguish a call from the same
words inside a comment, and it cannot tell which value reaches a sink.
"""

from __future__ import annotations

import re
from pathlib import Path

from .base import Finding

#: rule id -> (compiled pattern, CWEs, human-readable message)
RULES: dict[str, tuple[re.Pattern[str], tuple[str, ...], str]] = {
    "PAT-SQL-FSTRING": (
        re.compile(r"execute\w*\s*\(\s*f[\"']"),
        ("CWE-89",),
        "query executed from an f-string",
    ),
    "PAT-SQL-FORMAT": (
        re.compile(r"(SELECT|INSERT|UPDATE|DELETE)[^\n\"']*[\"']\s*(%|\.format\s*\(|\+)"),
        ("CWE-89",),
        "SQL text combined with a formatting or concatenation operator",
    ),
    "PAT-SQL-INTERP": (
        re.compile(r"(SELECT|INSERT|UPDATE|DELETE)[^\n]*(%s|\{\}|\{\w+\})"),
        ("CWE-89",),
        "SQL text containing an interpolation placeholder",
    ),
    "PAT-CMD-SHELL-TRUE": (
        re.compile(r"shell\s*=\s*True"),
        ("CWE-78",),
        "subprocess invoked through a shell",
    ),
    "PAT-CMD-OS-EXEC": (
        re.compile(r"os\.(system|popen)\s*\("),
        ("CWE-78",),
        "command executed through os.system/os.popen",
    ),
    "PAT-DESER-YAML": (
        re.compile(r"yaml\.(unsafe_)?load\s*\("),
        ("CWE-502",),
        "YAML parsed with a loader that may construct objects",
    ),
    "PAT-DESER-PICKLE": (
        re.compile(r"pickle\.loads?\s*\(|Unpickler\s*\(|from pickle import"),
        ("CWE-502",),
        "pickle used to decode data",
    ),
    "PAT-PATH-JOIN-OPEN": (
        re.compile(r"open\s*\(\s*(os\.path\.join|[\w.]+\s*\+)"),
        ("CWE-22",),
        "file opened from a joined or concatenated path",
    ),
    "PAT-PATH-PATHLIB": (
        re.compile(r"Path\s*\([^)]*\)\s*/\s*\w+"),
        ("CWE-22",),
        "path built by division on a pathlib.Path",
    ),
    "PAT-HASH-WEAK": (
        re.compile(r"hashlib\.(md5|sha1)\s*\(|hashlib\.new\s*\(\s*[\"'](md5|sha1)"),
        ("CWE-916", "CWE-327"),
        "weak digest algorithm",
    ),
    "PAT-RANDOM-MODULE": (
        re.compile(r"\brandom\.(random|randint|randrange|choice|getrandbits|seed|Random)\s*\("),
        ("CWE-330",),
        "value drawn from the random module",
    ),
    "PAT-SIG-DISABLED": (
        re.compile(r"verify\w*\s*=\s*False|[\"']none[\"']|VERIFY\w*\s*=\s*False"),
        ("CWE-347",),
        "signature verification disabled or algorithm 'none' accepted",
    ),
}

#: Absence rules fire when a marker is present and a required mitigation is not.
#: Checking for a *missing* call is the only way a text matcher can approach a
#: weakness whose signature is an omission, and it is a common heuristic.
ABSENCE_RULES: dict[str, tuple[re.Pattern[str], re.Pattern[str], tuple[str, ...], str]] = {
    "PAT-SIG-NO-COMPARE": (
        re.compile(r"partition\s*\(\s*[\"']\.[\"']\s*\)|split\s*\(\s*[\"']\.[\"']\s*\)"),
        re.compile(r"compare_digest"),
        ("CWE-347",),
        "token split without a constant-time signature comparison in the file",
    ),
}


class PatternOracle:
    """Matches rules against raw file text, comments and all."""

    name = "pattern"

    def version(self) -> str:
        return f"soda-pattern/{len(RULES) + len(ABSENCE_RULES)}-rules"

    def available(self) -> bool:
        return True

    def scan(self, files: list[Path]) -> dict[Path, list[Finding]]:
        results: dict[Path, list[Finding]] = {}
        for path in files:
            text = path.read_text(encoding="utf-8", errors="replace")
            findings: list[Finding] = []

            for rule_id, (pattern, cwes, message) in RULES.items():
                match = pattern.search(text)
                if match:
                    line = text.count("\n", 0, match.start()) + 1
                    findings.append(Finding(rule_id, cwes, line, message))

            for rule_id, (trigger, mitigation, cwes, message) in ABSENCE_RULES.items():
                match = trigger.search(text)
                if match and not mitigation.search(text):
                    line = text.count("\n", 0, match.start()) + 1
                    findings.append(Finding(rule_id, cwes, line, message))

            if findings:
                results[path] = findings
        return results
