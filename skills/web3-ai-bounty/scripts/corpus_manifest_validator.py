#!/usr/bin/env python3
"""Validate OOD corpus manifest counts, safety, and neutral case IDs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from overfitting_guard import assert_neutral_case_id


REQUIRED_CASE_FIELDS = {
    "case_id", "source_type", "protocol_type", "language", "framework", "is_vulnerable",
    "is_patched_control", "answer_key_path", "detector_allowed_paths", "detector_forbidden_paths",
    "allowed_detection_modes", "safety", "corpus_split",
}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace"))


def validate_manifest(root: Path) -> dict[str, Any]:
    manifest_path = root / "corpus_manifest.json"
    if not manifest_path.exists():
        raise SystemExit(f"missing manifest: {manifest_path}")
    manifest = load_json(manifest_path)
    blocks: list[str] = []
    cases = manifest.get("cases", [])
    bug_classes: set[str] = set()
    protocol_types: set[str] = set()
    counts = {"vulnerable": 0, "patched": 0, "holdout": 0}
    for case in cases:
        missing = REQUIRED_CASE_FIELDS - set(case)
        if missing:
            blocks.append(f"{case.get('case_id')}: missing fields {sorted(missing)}")
        try:
            assert_neutral_case_id(str(case.get("case_id")))
        except SystemExit as exc:
            blocks.append(str(exc))
        safety = case.get("safety", {})
        if safety.get("network_allowed") or safety.get("secrets_allowed") or safety.get("broadcast_allowed"):
            blocks.append(f"{case.get('case_id')}: unsafe permissions in manifest")
        split = case.get("corpus_split")
        if split in counts:
            counts[split] += 1
        protocol_types.add(str(case.get("protocol_type")))
        answer_path = root / str(case.get("answer_key_path"))
        if not answer_path.exists():
            blocks.append(f"{case.get('case_id')}: missing answer key {answer_path}")
        else:
            answer = load_json(answer_path)
            if answer.get("bug_class"):
                bug_classes.add(str(answer["bug_class"]))
    minimums = manifest.get("minimums", {})
    if counts["vulnerable"] < int(minimums.get("minimum_vulnerable_cases", 20)):
        blocks.append("not enough vulnerable cases")
    if counts["patched"] < int(minimums.get("minimum_patched_safe_cases", 20)):
        blocks.append("not enough patched cases")
    if counts["holdout"] < int(minimums.get("minimum_holdout_cases", 10)):
        blocks.append("not enough holdout cases")
    if len(bug_classes) < int(minimums.get("minimum_bug_classes", 10)):
        blocks.append("not enough bug classes")
    if len(protocol_types) < int(minimums.get("minimum_protocol_types", 5)):
        blocks.append("not enough protocol types")
    return {
        "status": "PASS" if not blocks else "FAIL",
        "blocks": blocks,
        "case_count": len(cases),
        "vulnerable_case_count": counts["vulnerable"],
        "patched_case_count": counts["patched"],
        "holdout_case_count": counts["holdout"],
        "bug_class_count": len(bug_classes),
        "protocol_type_count": len(protocol_types),
        "bug_classes": sorted(bug_classes),
        "protocol_types": sorted(protocol_types),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Validate OOD corpus manifest")
    p.add_argument("root")
    args = p.parse_args(argv)
    result = validate_manifest(Path(args.root))
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
