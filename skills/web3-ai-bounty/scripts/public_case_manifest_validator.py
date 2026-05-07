#!/usr/bin/env python3
"""Validate public historical corpus manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from public_case_license_checker import check_case_license
from public_case_sanitizer import case_name_leaks


PUBLIC_ROOT = Path(__file__).resolve().parents[1] / "benchmarks" / "public-historical-corpus"
REQUIRED_FIELDS = {"case_id", "source_type", "source_name", "source_url", "license_note", "commit_hash", "protocol_type", "language", "framework", "is_vulnerable", "is_patched_control", "is_holdout", "detector_allowed_paths", "detector_forbidden_paths", "answer_key_path", "writeup_path", "safety"}


def validate_public_manifest(root: Path = PUBLIC_ROOT) -> dict[str, Any]:
    manifest_path = root / "corpus_manifest.json"
    if not manifest_path.exists():
        return {"status": "BLOCKED", "public_case_import_status": "blocked_pending_approved_public_case_sources", "blocks": ["missing manifest"], "case_count": 0}
    manifest = json.loads(manifest_path.read_text(errors="replace"))
    cases = manifest.get("cases", [])
    blocks: list[str] = []
    for case in cases:
        missing = REQUIRED_FIELDS - set(case)
        if missing:
            blocks.append(f"{case.get('case_id')}: missing {sorted(missing)}")
        if case_name_leaks(str(case.get("case_id", ""))):
            blocks.append(f"{case.get('case_id')}: case id leaks vulnerability class")
        lic = check_case_license(case)
        if lic["status"] != "PASS":
            blocks.extend(f"{case.get('case_id')}: {b}" for b in lic["blocks"])
        safety = case.get("safety", {})
        if safety.get("network_allowed_during_detection") or safety.get("secrets_allowed") or safety.get("broadcast_allowed") or safety.get("deployment_scripts_allowed"):
            blocks.append(f"{case.get('case_id')}: unsafe detector permissions")
    bug_classes = set()
    protocols = {case.get("protocol_type") for case in cases}
    for case in cases:
        answer = root / str(case.get("answer_key_path", ""))
        if answer.exists():
            try:
                bug = json.loads(answer.read_text(errors="replace")).get("bug_class")
                if bug:
                    bug_classes.add(bug)
            except json.JSONDecodeError:
                blocks.append(f"{case.get('case_id')}: answer key is invalid JSON")
    return {
        "status": "PASS" if not blocks else "FAIL",
        "public_case_import_status": manifest.get("public_case_import_status", "unknown"),
        "blocks": blocks,
        "case_count": len(cases),
        "public_vulnerable_case_count": sum(1 for c in cases if c.get("is_vulnerable") and not c.get("is_holdout") and not c.get("is_patched_control")),
        "public_patched_case_count": sum(1 for c in cases if c.get("is_patched_control")),
        "public_holdout_case_count": sum(1 for c in cases if c.get("is_holdout")),
        "public_bug_class_count": len(bug_classes),
        "public_protocol_type_count": len([p for p in protocols if p]),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Validate public historical corpus manifest")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    args = p.parse_args(argv)
    result = validate_public_manifest(Path(args.root))
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
