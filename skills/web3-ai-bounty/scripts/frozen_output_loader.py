#!/usr/bin/env python3
"""Load and verify frozen generated artifacts for benchmark scoring."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from artifact_hasher import verify_frozen_report

PUBLIC_ROOT = Path(__file__).resolve().parents[1] / "benchmarks" / "public-historical-corpus"
ARTIFACT_SUFFIXES = ["confirmed_findings", "hypotheses", "manual_review_queue", "protocol_xray", "coverage", "lead_budget"]


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace"))


def case_ids_for_split(root: Path, split: str) -> list[str]:
    split_root = root / split
    if not split_root.exists():
        return []
    return sorted(p.name for p in split_root.iterdir() if p.is_dir())


def artifact_path(root: Path, case_id: str, suffix: str) -> Path:
    return root / "generated_reports" / f"{case_id}_{suffix}.json"


def verify_artifact(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"status": "FAIL", "path": str(path), "reason": "missing frozen generated artifact"}
    payload = load_json(path)
    blocks: list[str] = []
    if not verify_frozen_report(payload):
        blocks.append("frozen_at/report_hash missing or invalid")
    if payload.get("answer_key_loaded") or payload.get("answer_key_read_during_detection"):
        blocks.append("answer key was accessed during detection")
    if payload.get("writeup_read_during_detection"):
        blocks.append("report/writeup was accessed during detection")
    if payload.get("secrets_accessed"):
        blocks.append("secrets were accessed")
    if payload.get("broadcasts_used"):
        blocks.append("broadcasts were used")
    return {"status": "PASS" if not blocks else "FAIL", "path": str(path), "blocks": blocks, "payload": payload}


def load_case_outputs(root: Path, case_id: str, *, required_suffixes: list[str] | None = None) -> dict[str, Any]:
    suffixes = required_suffixes or ARTIFACT_SUFFIXES
    artifacts: dict[str, Any] = {}
    checks = []
    for suffix in suffixes:
        check = verify_artifact(artifact_path(root, case_id, suffix))
        checks.append({k: v for k, v in check.items() if k != "payload"})
        if check["status"] == "PASS":
            artifacts[suffix] = check["payload"]
    status = "PASS" if len(artifacts) == len(suffixes) and all(c["status"] == "PASS" for c in checks) else "FAIL"
    return {"status": status, "case_id": case_id, "artifacts": artifacts, "checks": checks}


def detector_changed_after_freeze(root: Path = PUBLIC_ROOT) -> dict[str, Any]:
    lock = root / "scoring" / "detector_v3_lead_generation_lock.json"
    if not lock.exists():
        return {"status": "FAIL", "reason": "missing detector lock", "detector_changed_after_baseline_freeze": True, "changed": []}
    payload = load_json(lock)
    skill_root = Path(__file__).resolve().parents[1]
    changed = []
    for row in payload.get("detector_files", []):
        path = skill_root / row.get("path", "")
        current = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else "MISSING"
        if current != row.get("sha256"):
            changed.append({"path": row.get("path"), "locked": row.get("sha256"), "current": current})
    return {"status": "PASS" if not changed else "FAIL", "detector_changed_after_baseline_freeze": bool(changed), "changed": changed}


def load_split_outputs(root: Path, split: str) -> dict[str, Any]:
    rows = [load_case_outputs(root, cid) for cid in case_ids_for_split(root, split)]
    return {"status": "PASS" if rows and all(r["status"] == "PASS" for r in rows) else "BLOCKED", "split": split, "case_count": len(rows), "cases": rows}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Verify frozen generated outputs")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="fresh-holdout")
    p.add_argument("--case-id", default="")
    args = p.parse_args(argv)
    root = Path(args.root)
    result = load_case_outputs(root, args.case_id) if args.case_id else load_split_outputs(root, args.split)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
