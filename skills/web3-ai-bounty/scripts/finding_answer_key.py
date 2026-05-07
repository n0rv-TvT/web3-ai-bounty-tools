#!/usr/bin/env python3
"""Answer-key loader used only after blind detection completes."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_vulnerable_answer_key(project_root: Path) -> list[dict[str, Any]]:
    expected_dir = project_root / "expected_findings"
    if not expected_dir.exists():
        return []
    return [json.loads(path.read_text(errors="replace")) for path in sorted(expected_dir.glob("*.json"))]


def load_safe_expected_results(project_root: Path) -> list[dict[str, Any]]:
    expected_dir = project_root / "expected_results"
    if not expected_dir.exists():
        return []
    return [json.loads(path.read_text(errors="replace")) for path in sorted(expected_dir.glob("*.json"))]


def load_answer_key(project_root: Path, *, safe_controls: bool = False) -> dict[str, Any]:
    if safe_controls:
        rows = load_safe_expected_results(project_root)
        return {"type": "safe_controls", "fixture_count": len(rows), "results": rows}
    rows = load_vulnerable_answer_key(project_root)
    return {"type": "vulnerable", "fixture_count": len(rows), "findings": rows}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Load benchmark answer key after blind detection")
    p.add_argument("project_root")
    p.add_argument("--safe-controls", action="store_true")
    args = p.parse_args(argv)
    print(json.dumps(load_answer_key(Path(args.project_root), safe_controls=args.safe_controls), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
