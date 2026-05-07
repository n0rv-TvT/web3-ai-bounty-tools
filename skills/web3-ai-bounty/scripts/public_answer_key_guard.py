#!/usr/bin/env python3
"""Answer-key/writeup isolation guard for public historical benchmarks."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from artifact_hasher import verify_frozen_report


FORBIDDEN_DURING_DETECTION = (
    "expected_findings/", "public_writeups/", "reports/", "audit_reports/", "issues/", "README.md"
)


def forbidden_hit(path: str) -> str | None:
    normalized = path.replace("\\", "/")
    for forbidden in FORBIDDEN_DURING_DETECTION:
        if normalized == forbidden.rstrip("/") or normalized.startswith(forbidden):
            return forbidden
    return None


def validate_detection_read_set(read_files: list[str], *, source_only: bool = False) -> dict[str, Any]:
    blocks: list[dict[str, str]] = []
    for path in read_files:
        hit = forbidden_hit(path)
        if hit:
            blocks.append({"path": path, "reason": f"forbidden during detection: {hit}"})
        if source_only and (path.startswith("test/") or "/test/" in path):
            blocks.append({"path": path, "reason": "source-only mode cannot read tests"})
    return {"status": "PASS" if not blocks else "FAIL", "blocks": blocks}


def validate_report_before_scoring(report: dict[str, Any]) -> dict[str, Any]:
    blocks: list[str] = []
    if report.get("answer_key_loaded") or report.get("answer_key_read_during_detection"):
        blocks.append("answer key was accessed during detection")
    if report.get("writeup_read_during_detection"):
        blocks.append("writeup was accessed during detection")
    if not verify_frozen_report(report):
        blocks.append("report was not frozen/hashed before scoring")
    return {"status": "PASS" if not blocks else "FAIL", "blocks": blocks}


def invalidate_on_answer_key_access(report: dict[str, Any]) -> bool:
    return bool(report.get("answer_key_loaded") or report.get("answer_key_read_during_detection") or report.get("writeup_read_during_detection"))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Validate public benchmark report isolation")
    p.add_argument("report_json")
    args = p.parse_args(argv)
    report = json.loads(Path(args.report_json).read_text(errors="replace"))
    result = validate_report_before_scoring(report)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
