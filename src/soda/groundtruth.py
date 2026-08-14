"""Establishing the ground truth that every oracle is scored against."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from .models import Case, GroundTruth, Variant

#: Witnesses are small and deterministic; the slowest is a bounded dictionary
#: attack. Anything past this is a hang, not a slow result.
DEFAULT_TIMEOUT_S = 120.0


def evaluate(case: Case, variant: Variant, timeout: float = DEFAULT_TIMEOUT_S) -> GroundTruth:
    """Run the variant's functional contract and exploit witness in a subprocess."""
    cmd = [
        sys.executable,
        "-m",
        "soda._probe",
        str(case.directory),
        str(variant.path),
    ]
    env_root = str(Path(__file__).resolve().parents[1])

    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=env_root,
        )
    except subprocess.TimeoutExpired:
        return GroundTruth(
            case_id=case.case_id,
            variant_id=variant.variant_id,
            functional_ok=False,
            exploited=False,
            label=GroundTruth.label_for(False, False),
            elapsed_s=timeout,
            detail=f"probe timed out after {timeout}s",
        )

    stdout = proc.stdout.strip()
    if not stdout:
        return GroundTruth(
            case_id=case.case_id,
            variant_id=variant.variant_id,
            functional_ok=False,
            exploited=False,
            label=GroundTruth.label_for(False, False),
            elapsed_s=0.0,
            detail=f"probe produced no output (rc={proc.returncode}): {proc.stderr[:400]}",
        )

    payload = json.loads(stdout)
    functional_ok = bool(payload["functional_ok"])
    exploited = bool(payload["exploited"])
    return GroundTruth(
        case_id=case.case_id,
        variant_id=variant.variant_id,
        functional_ok=functional_ok,
        exploited=exploited,
        label=GroundTruth.label_for(functional_ok, exploited),
        elapsed_s=float(payload.get("elapsed_s", 0.0)),
        detail=str(payload.get("detail", "")),
    )
