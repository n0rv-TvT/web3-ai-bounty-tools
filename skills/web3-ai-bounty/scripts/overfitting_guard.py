#!/usr/bin/env python3
"""Answer-key isolation and anti-overfitting checks for OOD benchmarks."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from artifact_hasher import verify_frozen_report


BUG_CLASS_TOKENS = {
    "reentrancy", "oracle", "erc4626", "inflation", "reward", "signature", "replay",
    "proxy", "initialization", "access", "control", "decimal", "rounding", "bridge",
    "double", "finalize", "malicious", "accounting", "cross", "function", "mev",
}

FORBIDDEN_ALWAYS = ("expected_findings/", "expected_results/", "writeups/", "reports/", "README.md", "corpus_manifest.json")


def path_has_forbidden_prefix(path: str, forbidden: list[str] | tuple[str, ...]) -> str | None:
    normalized = path.replace("\\", "/")
    for item in forbidden:
        f = item.replace("\\", "/")
        if normalized == f.rstrip("/") or normalized.startswith(f):
            return item
    return None


def assert_neutral_case_id(case_id: str) -> None:
    lowered = case_id.lower().replace("-", "_")
    tokens = set(lowered.split("_")) | {lowered}
    leaked = sorted(tokens.intersection(BUG_CLASS_TOKENS))
    if leaked:
        raise SystemExit(f"case_id leaks bug class tokens: {case_id} -> {leaked}")


def validate_detection_access(read_files: list[str], *, mode: str, detector_forbidden_paths: list[str] | None = None) -> dict[str, Any]:
    case_forbidden = list(detector_forbidden_paths or [])
    if mode in {"source-plus-tests", "holdout", "patched-controls"}:
        case_forbidden = [item for item in case_forbidden if item.rstrip("/") != "test"]
    forbidden = list(FORBIDDEN_ALWAYS) + case_forbidden
    blocks: list[dict[str, str]] = []
    for path in read_files:
        hit = path_has_forbidden_prefix(path, forbidden)
        if hit:
            blocks.append({"path": path, "reason": f"forbidden path matched {hit}"})
        if mode == "source-only" and (path.startswith("test/") or "/test/" in path):
            blocks.append({"path": path, "reason": "source-only mode cannot read tests"})
    return {"status": "PASS" if not blocks else "FAIL", "blocks": blocks, "read_file_count": len(read_files)}


def validate_detection_result(result: dict[str, Any], *, mode: str, case: dict[str, Any]) -> dict[str, Any]:
    assert_neutral_case_id(str(case.get("case_id")))
    access = validate_detection_access(result.get("read_files", []), mode=mode, detector_forbidden_paths=case.get("detector_forbidden_paths", []))
    blocks = list(access.get("blocks", []))
    if result.get("answer_key_read"):
        blocks.append({"path": "expected_findings", "reason": "answer key was read during detection"})
    return {"status": "PASS" if not blocks else "FAIL", "blocks": blocks, "case_id": case.get("case_id"), "mode": mode}


def validate_frozen_before_scoring(report: dict[str, Any]) -> dict[str, Any]:
    blocks: list[str] = []
    if report.get("answer_key_loaded"):
        blocks.append("generated report says answer key was loaded before scoring")
    if not verify_frozen_report(report):
        blocks.append("generated report is missing or has invalid pre-score hash")
    return {"status": "PASS" if not blocks else "FAIL", "blocks": blocks}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Validate OOD benchmark anti-overfitting properties")
    p.add_argument("report_json")
    args = p.parse_args(argv)
    report = json.loads(Path(args.report_json).read_text(errors="replace"))
    result = validate_frozen_before_scoring(report)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
