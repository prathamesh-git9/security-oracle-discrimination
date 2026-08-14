"""Collect independent before-and-after evidence from reviewed advisories.

The synthetic corpus can be shipped because it was written for this project.
The production files cannot: they are other people's code under their own
licences. Consequently the repository ships provenance in a manifest and the
resulting measurements, never the fetched source. The default cache therefore
lives in the ignored ``production/cache/`` working directory and can always be
reconstructed from the recorded revisions.

Collection is deliberately tolerant of gaps. Repositories disappear, commits
become private, and paths move; none of those events is evidence that an oracle
missed a weakness. They are counted and omitted instead of turning an
availability accident into a finding or aborting a long collection run.
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from .. import cwe

DEFAULT_CACHE_ROOT = Path("production/cache")

_COMMIT_URL = re.compile(
    r"^https?://(?:www\.)?github\.com/([^/]+)/([^/]+)/commit/"
    r"([0-9a-f]{7,64})(?:[/?#].*)?$",
    re.IGNORECASE,
)

_COUNT_KEYS = (
    "advisories",
    "pairs",
    "no_commit_reference",
    "duplicate_commits",
    "uncovered_advisories",
    "merge_commits",
    "too_broad",
    "no_python_files",
    "fetch_failures",
)


@dataclass(frozen=True)
class Pair:
    """One file on the two sides of a maintainer's security fix."""

    ghsa: str
    cve: str | None
    cwes: tuple[str, ...]
    severity: str
    repo: str
    sha: str
    parent_sha: str
    path: str
    additions: int
    deletions: int
    solo: bool


def _fresh_counts() -> dict[str, int]:
    return dict.fromkeys(_COUNT_KEYS, 0)


class _PairList(list[Pair]):
    """Keep collection gaps beside the observations they qualify."""

    def __init__(
        self,
        pairs=(),
        counts: dict[str, int] | None = None,
    ) -> None:
        super().__init__(pairs)
        self.counts = counts if counts is not None else _fresh_counts()

    def __getitem__(self, item):
        selected = super().__getitem__(item)
        if isinstance(item, slice):
            return _PairList(selected, self.counts)
        return selected


_LAST_COUNTS = _fresh_counts()


class _PairFetchError(RuntimeError):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason


def _gh_api(endpoint: str) -> object | None:
    """Make one lost repository a recorded gap rather than a lost run."""
    if endpoint.startswith("/"):
        raise ValueError("gh api endpoints must not have a leading slash")

    try:
        proc = subprocess.run(  # noqa: S603 - fixed executable and no shell
            ["gh", "api", endpoint],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return None

    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, TypeError):
        return None


def _advisory_cwes(advisory: dict) -> tuple[str, ...]:
    identifiers: list[str] = []
    for entry in advisory.get("cwes", []):
        if isinstance(entry, dict):
            identifier = entry.get("cwe_id")
        else:
            identifier = entry
        if isinstance(identifier, str):
            identifiers.append(identifier)
    return cwe.covered_cwes(identifiers)


def _commit_reference(advisory: dict) -> tuple[str, str] | None:
    for reference in advisory.get("references", []):
        url = reference.get("url") if isinstance(reference, dict) else reference
        if not isinstance(url, str):
            continue
        match = _COMMIT_URL.match(url)
        if match:
            owner, name, sha = match.groups()
            return f"{owner}/{name}", sha
    return None


def _is_kept_python_file(entry: object) -> bool:
    if not isinstance(entry, dict) or entry.get("status") != "modified":
        return False
    filename = entry.get("filename")
    if not isinstance(filename, str) or not filename.lower().endswith(".py"):
        return False

    parts = filename.replace("\\", "/").split("/")
    lowered = [part.lower() for part in parts]
    basename = lowered[-1]
    if any(part in {"test", "tests", "testing"} for part in lowered[:-1]):
        return False
    return not (
        basename.startswith("test_")
        or basename.endswith("_test.py")
        or basename in {"version.py", "conftest.py"}
    )


def build_manifest(per_cwe: int = 60, max_py_files: int = 4) -> list[Pair]:
    """Prefer narrow fixes so a changed file is credible security evidence."""
    if per_cwe < 1:
        raise ValueError("per_cwe must be positive")
    if max_py_files < 1:
        raise ValueError("max_py_files must be positive")

    global _LAST_COUNTS
    counts = _fresh_counts()
    _LAST_COUNTS = counts
    pairs = _PairList(counts=counts)
    seen_commits: set[tuple[str, str]] = set()

    for covered in cwe.COVERED:
        number = covered.removeprefix("CWE-")
        endpoint = (
            f"advisories?ecosystem=pip&cwes={number}&per_page={per_cwe}"
            "&type=reviewed"
        )
        advisories = _gh_api(endpoint)
        if not isinstance(advisories, list):
            counts["fetch_failures"] += 1
            continue

        for advisory in advisories:
            if not isinstance(advisory, dict):
                counts["fetch_failures"] += 1
                continue
            counts["advisories"] += 1

            covered_ids = _advisory_cwes(advisory)
            if not covered_ids:
                counts["uncovered_advisories"] += 1
                continue

            reference = _commit_reference(advisory)
            if reference is None:
                counts["no_commit_reference"] += 1
                continue
            repo, referenced_sha = reference
            commit_key = (repo.lower(), referenced_sha.lower())
            if commit_key in seen_commits:
                counts["duplicate_commits"] += 1
                continue
            seen_commits.add(commit_key)

            commit = _gh_api(f"repos/{repo}/commits/{referenced_sha}")
            if not isinstance(commit, dict):
                counts["fetch_failures"] += 1
                continue

            parents = commit.get("parents")
            if not isinstance(parents, list) or len(parents) != 1:
                counts["merge_commits"] += 1
                continue
            parent_sha = parents[0].get("sha")
            if not isinstance(parent_sha, str) or not parent_sha:
                counts["fetch_failures"] += 1
                continue

            files = commit.get("files")
            if not isinstance(files, list):
                counts["fetch_failures"] += 1
                continue
            python_files = [entry for entry in files if _is_kept_python_file(entry)]
            if not python_files:
                counts["no_python_files"] += 1
                continue
            if len(python_files) > max_py_files:
                counts["too_broad"] += 1
                continue

            ghsa = advisory.get("ghsa_id")
            if not isinstance(ghsa, str) or not ghsa:
                counts["fetch_failures"] += 1
                continue
            cve = advisory.get("cve_id")
            canonical_sha = commit.get("sha")
            sha = canonical_sha if isinstance(canonical_sha, str) else referenced_sha
            solo = len(python_files) == 1

            for entry in python_files:
                pairs.append(
                    Pair(
                        ghsa=ghsa,
                        cve=cve if isinstance(cve, str) else None,
                        cwes=covered_ids,
                        severity=str(advisory.get("severity", "")),
                        repo=repo,
                        sha=sha,
                        parent_sha=parent_sha,
                        path=str(entry["filename"]),
                        additions=int(entry.get("additions", 0) or 0),
                        deletions=int(entry.get("deletions", 0) or 0),
                        solo=solo,
                    )
                )

    pairs.sort(key=lambda pair: (pair.ghsa, pair.path))
    counts["pairs"] = len(pairs)
    return pairs


def _counts_for(pairs: list[Pair]) -> dict[str, int]:
    counts = getattr(pairs, "counts", None)
    return counts if isinstance(counts, dict) else _LAST_COUNTS


def write_manifest(pairs: list[Pair], path: Path) -> Path:
    """Preserve collection gaps because absence is part of the study's limits."""
    counts = {key: int(value) for key, value in _counts_for(pairs).items()}
    counts["pairs"] = len(pairs)
    ordered = sorted(pairs, key=lambda pair: (pair.ghsa, pair.path))
    payload = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "counts": counts,
        "pairs": [asdict(pair) for pair in ordered],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def load_manifest(path: Path) -> list[Pair]:
    """Restore provenance and its gaps as one inseparable collection."""
    global _LAST_COUNTS
    payload = json.loads(path.read_text(encoding="utf-8"))
    counts_payload = payload.get("counts", {})
    counts = _fresh_counts()
    if isinstance(counts_payload, dict):
        counts.update(
            {
                str(key): int(value)
                for key, value in counts_payload.items()
                if isinstance(value, int)
            }
        )

    pairs = _PairList(counts=counts)
    for entry in payload["pairs"]:
        values = dict(entry)
        values["cwes"] = tuple(values["cwes"])
        pairs.append(Pair(**values))
    counts["pairs"] = len(pairs)
    _LAST_COUNTS = counts
    return pairs


def _cache_paths(pair: Pair, cache_root: Path) -> tuple[Path, Path]:
    flattened = pair.path.replace("\\", "/").replace("/", "__")
    root = cache_root / pair.ghsa / pair.sha[:12]
    return root / "pre" / flattened, root / "post" / flattened


def _fetch_image(pair: Pair, revision: str, target: Path, side: str) -> None:
    encoded_path = quote(pair.path.replace("\\", "/"), safe="/")
    endpoint = f"repos/{pair.repo}/contents/{encoded_path}?ref={revision}"
    payload = _gh_api(endpoint)
    if not isinstance(payload, dict) or not isinstance(payload.get("content"), str):
        raise _PairFetchError(
            f"{side}_image_failures",
            f"{side}-image unavailable at {revision[:12]}",
        )

    try:
        compact = "".join(payload["content"].split())
        source = base64.b64decode(compact, validate=True)
    except (ValueError, TypeError) as exc:
        raise _PairFetchError(
            f"{side}_image_failures",
            f"{side}-image returned invalid base64 at {revision[:12]}",
        ) from exc

    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_bytes(source)
    temporary.replace(target)


def fetch_pair(
    pair: Pair,
    cache_root: Path = DEFAULT_CACHE_ROOT,
) -> tuple[Path, Path]:
    """Materialise both labels only when the pair is complete and comparable."""
    pre, post = _cache_paths(pair, cache_root)
    if pre.is_file() and post.is_file():
        return pre, post
    if not pre.is_file():
        _fetch_image(pair, pair.parent_sha, pre, "pre")
    if not post.is_file():
        _fetch_image(pair, pair.sha, post, "post")
    return pre, post


def fetch_all(
    pairs: list[Pair],
    cache_root: Path = DEFAULT_CACHE_ROOT,
    progress=None,
) -> list[tuple[Pair, Path, Path]]:
    """Keep availability gaps out of the oracle's apparent error rate."""
    counts = _counts_for(pairs)
    say = progress or (lambda _message: None)
    fetched: list[tuple[Pair, Path, Path]] = []
    total = len(pairs)

    for index, pair in enumerate(pairs, start=1):
        say(f"fetching {index}/{total}: {pair.ghsa} {pair.path}")
        try:
            pre, post = fetch_pair(pair, cache_root)
        except _PairFetchError as exc:
            counts["fetch_failures"] = counts.get("fetch_failures", 0) + 1
            counts[exc.reason] = counts.get(exc.reason, 0) + 1
            say(f"  skipped {pair.ghsa} {pair.path}: {exc}")
            continue
        fetched.append((pair, pre, post))

    return fetched
