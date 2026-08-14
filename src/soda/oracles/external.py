"""Adapters for the two production static analysers this study audits.

Both are invoked exactly as a benchmark harness would invoke them: point the tool
at files, take its JSON, believe what it says about itself. In particular the CWE
attached to a finding is the tool's own claim, never our interpretation of the
rule -- otherwise the audit would be scoring our reading of the rule catalogue
rather than the tool.

Both are run once over the whole corpus rather than once per file. That is not
only faster; it is also how these tools are used in practice, and it removes any
chance that per-file invocation overhead changes what they report.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .base import Finding, OracleError, normalise_cwes

TIMEOUT_S = 1800.0

#: Files are handed to the tools in batches. A single invocation carrying every
#: path is simpler, but Windows caps a command line at about 32k characters and
#: the production study scans a few hundred absolute paths -- comfortably enough
#: to trip it. A truncated argument list would look like an oracle that found
#: nothing, which is the most dangerous way for this study to fail.
BATCH_SIZE = 50

#: Semgrep pays a large fixed cost per invocation loading and compiling its rule
#: pack, so it gets far bigger batches than bandit. 120 absolute paths is roughly
#: 18k characters, which stays clear of the 32k limit while paying that cost once
#: per batch instead of once per fifty files.
SEMGREP_BATCH_SIZE = 120

#: Real project files are orders of magnitude larger than the corpus variants,
#: and a single pathological file can hold a rule engine for minutes. Bounding
#: per-rule time keeps a scan finite; semgrep reports what it skipped, and a
#: skipped file is recorded as "no finding", which is the honest reading.
SEMGREP_RULE_TIMEOUT_S = 10


def _batched(files: list[Path], size: int = BATCH_SIZE):
    for start in range(0, len(files), size):
        yield files[start : start + size]


def _run(cmd: list[str], timeout: float = TIMEOUT_S) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )


class BanditOracle:
    """PyCQA bandit, the default Python security linter in the SE literature."""

    name = "bandit"

    def __init__(self, python: str | None = None) -> None:
        self._python = python or sys.executable

    def version(self) -> str:
        try:
            proc = _run([self._python, "-m", "bandit", "--version"], timeout=60)
        except Exception:  # noqa: BLE001
            return "bandit/unknown"
        first = (proc.stdout or proc.stderr).strip().splitlines()
        return first[0].strip() if first else "bandit/unknown"

    def available(self) -> bool:
        try:
            proc = _run([self._python, "-c", "import bandit"], timeout=60)
        except Exception:  # noqa: BLE001
            return False
        return proc.returncode == 0

    def scan(self, files: list[Path]) -> dict[Path, list[Finding]]:
        if not files:
            return {}
        results: dict[Path, list[Finding]] = {}
        for batch in _batched(files):
            cmd = [
                self._python,
                "-m",
                "bandit",
                "-f",
                "json",
                "-q",
                *[str(f) for f in batch],
            ]
            proc = _run(cmd)
            # bandit exits 1 when it has findings, which is a success for us.
            if proc.returncode not in (0, 1) or not proc.stdout.strip():
                raise OracleError(
                    f"bandit failed (rc={proc.returncode}): {proc.stderr[:500]}"
                )

            payload = json.loads(proc.stdout)
            for item in payload.get("results", []):
                path = Path(item["filename"]).resolve()
                results.setdefault(path, []).append(
                    Finding(
                        rule_id=str(item.get("test_id", "")),
                        cwes=normalise_cwes(item.get("issue_cwe")),
                        line=int(item.get("line_number", 0) or 0),
                        message=str(item.get("issue_text", ""))[:300],
                        severity=str(item.get("issue_severity", "")),
                    )
                )
        return results


class SemgrepOracle:
    """Semgrep OSS with a published ruleset.

    The ruleset is pinned by name in :attr:`config`; semgrep resolves and caches
    it locally. The registry version in force at scan time is part of the result,
    so the version string records it as far as the tool exposes it.
    """

    name = "semgrep"

    def __init__(
        self,
        config: str = "p/python",
        executable: str | None = None,
        name: str | None = None,
    ) -> None:
        self.config = config
        # A semgrep result is a result *about a ruleset*, so the ruleset belongs
        # in the oracle's identity. Auditing two of them is how this study
        # separates "semgrep cannot see this" from "p/python has no rule for it".
        self.name = name or f"semgrep:{config}"
        self._exe = executable or shutil.which("semgrep")

    def version(self) -> str:
        if not self._exe:
            return "semgrep/absent"
        try:
            proc = _run([self._exe, "--version"], timeout=120)
        except Exception:  # noqa: BLE001
            return "semgrep/unknown"
        return f"semgrep/{proc.stdout.strip()} config={self.config}"

    def available(self) -> bool:
        return bool(self._exe)

    def scan(self, files: list[Path]) -> dict[Path, list[Finding]]:
        if not files:
            return {}
        if not self._exe:
            raise OracleError("semgrep executable not found")

        results: dict[Path, list[Finding]] = {}
        for batch in _batched(files, SEMGREP_BATCH_SIZE):
            cmd = [
                self._exe,
                "scan",
                f"--config={self.config}",
                "--json",
                "--quiet",
                "--metrics=off",
                "--no-git-ignore",
                f"--timeout={SEMGREP_RULE_TIMEOUT_S}",
                "--timeout-threshold=3",
                *[str(f) for f in batch],
            ]
            proc = _run(cmd)
            if not proc.stdout.strip():
                raise OracleError(
                    f"semgrep produced no JSON (rc={proc.returncode}): "
                    f"{proc.stderr[:500]}"
                )

            payload = json.loads(proc.stdout)
            for item in payload.get("results", []):
                path = Path(item["path"]).resolve()
                extra = item.get("extra", {})
                metadata = extra.get("metadata", {})
                results.setdefault(path, []).append(
                    Finding(
                        rule_id=str(item.get("check_id", "")),
                        cwes=normalise_cwes(metadata.get("cwe")),
                        line=int(item.get("start", {}).get("line", 0) or 0),
                        message=str(extra.get("message", ""))[:300],
                        severity=str(extra.get("severity", "")),
                    )
                )
        return results
