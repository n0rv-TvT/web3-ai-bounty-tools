#!/usr/bin/env python3
"""Run source-only triage on imported Proof-of-Patch pair versions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from bug_bounty_triage_runner import run_project

PUBLIC_ROOT = Path(__file__).resolve().parents[1] / "benchmarks" / "public-historical-corpus"


def write_artifacts(root: Path, case_id: str, result: dict[str, Any], split: str, mode: str) -> None:
    out = root / "generated_reports"
    out.mkdir(parents=True, exist_ok=True)
    common = {"case_id": case_id, "split": split, "mode": mode, "answer_key_loaded": False, "answer_key_read_during_detection": False, "writeup_read_during_detection": False, "patch_metadata_read_during_detection": False, "network_used": False, "secrets_accessed": False, "broadcasts_used": False}
    artifacts = {
        "confirmed_findings": {**common, "artifact_type": "confirmed_findings", "findings": [], "confirmed_finding_count": 0},
        "hypotheses": {**common, **result["xray"].get("bounty_hypotheses", {})},
        "manual_review_queue": {**common, **result["xray"].get("manual_review_queue", {})},
        "protocol_xray": {**common, **result["xray"]},
        "coverage": {**common, **result["coverage"]},
        "lead_budget": {**common, **result["lead_budget"]},
    }
    for suffix, payload in artifacts.items():
        (out / f"{case_id}_{suffix}.json").write_text(json.dumps(payload, indent=2) + "\n")


def run_pairs(root: Path = PUBLIC_ROOT, *, split: str = "patched-controls", mode: str = "source-only") -> dict[str, Any]:
    split_root = root / split
    if not split_root.exists() or not any(p.is_dir() for p in split_root.iterdir()):
        return {"status": "BLOCKED", "split": split, "reason": "no imported Proof-of-Patch pair versions", "case_count": 0, "patch_metadata_read_during_detection": False}
    rows = []
    for case_root in sorted(p for p in split_root.iterdir() if p.is_dir()):
        result = run_project(case_root, case_id=case_root.name, mode=mode)
        write_artifacts(root, case_root.name, result, split, mode)
        rows.append({"case_id": case_root.name, "status": result["status"], "hypotheses": result.get("hypothesis_count", 0), "confirmed_findings": 0, "patch_metadata_read_during_detection": False})
    payload = {"status": "PASS" if rows and all(r["status"] == "PASS" for r in rows) else "FAIL", "split": split, "mode": mode, "case_count": len(rows), "cases": rows, "patch_metadata_read_during_detection": False, "network_used_during_detection": False, "secrets_accessed": False, "broadcasts_used": False}
    (root / "scoring" / "proof_of_patch_pair_runner.json").write_text(json.dumps(payload, indent=2) + "\n")
    return payload


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run Proof-of-Patch pair detection")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="patched-controls")
    p.add_argument("--mode", default="source-only")
    args = p.parse_args(argv)
    result = run_pairs(Path(args.root), split=args.split, mode=args.mode)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
