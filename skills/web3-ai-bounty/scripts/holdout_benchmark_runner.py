#!/usr/bin/env python3
"""CLI for OOD real-world/holdout benchmark modes."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from audit_run_orchestrator import run_mode
from real_world_corpus_builder import DEFAULT_ROOT, build_corpus


VALID_MODES = {"source-only", "source-plus-tests", "patched-controls", "holdout", "score-only"}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run OOD Web3 benchmark modes")
    p.add_argument("--mode", required=True, choices=sorted(VALID_MODES))
    p.add_argument("--root", default=str(DEFAULT_ROOT))
    p.add_argument("--rebuild", action="store_true")
    args = p.parse_args(argv)
    root = Path(args.root)
    if args.rebuild or not (root / "corpus_manifest.json").exists():
        build_corpus(root, force=args.rebuild)
    result = run_mode(root, mode=args.mode)
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
