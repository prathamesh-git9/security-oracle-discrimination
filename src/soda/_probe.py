"""Subprocess entry point that earns a variant's security label by running it.

This runs in its own process for three reasons. Exploit witnesses in the corpus
really do execute attacker-controlled input -- that is the whole point -- so a
witness may leave module state behind, spawn a shell, or kill the interpreter.
None of that may be allowed to reach the audit process or leak between variants.

Invoked as ``python -m soda._probe <case_dir> <variant_path>``; prints one JSON
object on stdout and nothing else.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import time
import traceback
import uuid
from pathlib import Path
from types import ModuleType


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    # Registering the module before execution keeps dataclasses, pickle and
    # anything else that looks itself up by __module__ working inside variants.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main(argv: list[str]) -> int:
    case_dir = Path(argv[1]).resolve()
    variant_path = Path(argv[2]).resolve()

    result = {
        "functional_ok": False,
        "exploited": False,
        "detail": "",
        "elapsed_s": 0.0,
    }
    started = time.perf_counter()

    try:
        harness = _load(case_dir / "harness.py", f"harness_{uuid.uuid4().hex}")

        # Phase 1 -- functional contract. A variant that cannot do its job is not
        # evidence about anything, so this gates the security question entirely.
        with tempfile.TemporaryDirectory(prefix="soda-fn-") as tmp:
            module = _load(variant_path, f"variant_fn_{uuid.uuid4().hex}")
            try:
                harness.functional(module, Path(tmp))
                result["functional_ok"] = True
            except Exception as exc:  # noqa: BLE001 - any failure is a failure
                result["detail"] = f"functional: {type(exc).__name__}: {exc}"

        # Phase 2 -- exploit witness, against a freshly imported module so that
        # module-level state (seeded RNGs, caches) is identical to phase 1.
        if result["functional_ok"]:
            with tempfile.TemporaryDirectory(prefix="soda-ex-") as tmp:
                module = _load(variant_path, f"variant_ex_{uuid.uuid4().hex}")
                try:
                    result["exploited"] = bool(harness.exploit(module, Path(tmp)))
                except Exception as exc:  # noqa: BLE001
                    # A witness that crashes has not demonstrated exploitation.
                    result["detail"] = f"witness: {type(exc).__name__}: {exc}"
                    result["exploited"] = False
    except Exception:  # noqa: BLE001
        result["detail"] = "probe: " + traceback.format_exc(limit=3)

    result["elapsed_s"] = round(time.perf_counter() - started, 4)
    sys.stdout.write(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
