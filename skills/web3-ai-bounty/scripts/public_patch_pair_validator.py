#!/usr/bin/env python3
"""Validate vulnerable/patched public benchmark case pairs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


PUBLIC_ROOT = Path(__file__).resolve().parents[1] / "benchmarks" / "public-historical-corpus"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace"))


def patch_touches_root_area(vulnerable_root: Path, patched_root: Path, expected: dict[str, Any]) -> bool:
    rel = expected.get("source_file", "")
    if not rel:
        return False
    v = vulnerable_root / rel
    p = patched_root / rel
    if not v.exists() or not p.exists():
        return False
    return v.read_text(errors="replace") != p.read_text(errors="replace")


def validate_pair(vulnerable_case: dict[str, Any], patched_case: dict[str, Any], root: Path = PUBLIC_ROOT) -> dict[str, Any]:
    blocks: list[str] = []
    if vulnerable_case.get("protocol_type") != patched_case.get("protocol_type"):
        blocks.append("protocol type mismatch")
    expected = load_json(root / vulnerable_case["answer_key_path"])
    if not patch_touches_root_area(root / "vulnerable" / vulnerable_case["case_id"], root / "patched" / patched_case["case_id"], expected):
        blocks.append("patch does not touch expected root-cause source file")
    report_path = root / "generated_reports" / f"{patched_case['case_id']}.json"
    if report_path.exists():
        report = load_json(report_path)
        if any(f.get("report_ready") for f in report.get("findings", [])):
            blocks.append("patched control produced report-ready finding")
    return {"status": "PASS" if not blocks else "FAIL", "blocks": blocks, "vulnerable_case_id": vulnerable_case.get("case_id"), "patched_case_id": patched_case.get("case_id")}


def find_matching_patch(manifest: dict[str, Any], vulnerable_case: dict[str, Any]) -> dict[str, Any] | None:
    for case in manifest.get("cases", []):
        if case.get("is_patched_control") and case.get("protocol_type") == vulnerable_case.get("protocol_type"):
            return case
    return None


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Validate public patch pairs")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    args = p.parse_args(argv)
    root = Path(args.root)
    manifest = load_json(root / "corpus_manifest.json") if (root / "corpus_manifest.json").exists() else {"cases": []}
    results = []
    for case in manifest.get("cases", []):
        if case.get("is_vulnerable") and not case.get("is_holdout") and not case.get("is_patched_control"):
            patch = find_matching_patch(manifest, case)
            if patch:
                results.append(validate_pair(case, patch, root))
            else:
                results.append({"status": "FAIL", "blocks": ["missing patch"], "vulnerable_case_id": case.get("case_id")})
    print(json.dumps({"status": "PASS" if all(r["status"] == "PASS" for r in results) else "FAIL", "results": results}, indent=2))
    return 0 if all(r["status"] == "PASS" for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
