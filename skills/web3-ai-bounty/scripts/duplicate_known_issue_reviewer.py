#!/usr/bin/env python3
"""Local duplicate/known-issue review for the confirmed post-hoc regression."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT
from report_ready_closure_utils import CONFIRMED_CANDIDATE_ID, closure_path, load_evidence, load_json, safe_id, safety_metadata, write_json


def review_duplicate_known_issue(root: Path = PUBLIC_ROOT, *, candidate_id: str = CONFIRMED_CANDIDATE_ID) -> dict[str, Any]:
    evidence = load_evidence(root, candidate_id)
    memory = load_json(root / "scoring" / "poc_vertical_slice_feedback_memory.json", {"entries": []})
    batch = load_json(root / "scoring" / "poc_vertical_slice_batch_result.json", {"results": []})
    same_root = []
    for row in batch.get("results", []):
        if row.get("candidate_id") != candidate_id and row.get("pair_id") == evidence.get("pair_id"):
            other_id = row.get("candidate_id")
            other_evidence = load_json(root / "scoring" / f"poc_vertical_slice_{safe_id(str(other_id))}_evidence_package.json", {})
            if other_evidence and other_evidence.get("function") != evidence.get("function"):
                continue
            if row.get("killed") is True and other_evidence.get("vulnerable_code_path") != evidence.get("vulnerable_code_path"):
                continue
            same_root.append(other_id)
    memory_hits = [entry for entry in memory.get("entries", []) if candidate_id in str(entry.get("finding_id", "")) or "investmentmanager | requestdeposit" in str(entry.get("signature", "")).lower()]
    duplicate_status = "UNIQUE" if not same_root else "SAME_ROOT_CAUSE"
    payload = {
        "candidate_id": candidate_id,
        "duplicate_status": duplicate_status,
        "known_issue_status": "KNOWN_PATCHED_CONTROL",
        "counts_toward_readiness": False,
        "fresh_bounty_evidence": False,
        "blocks": [],
        "fresh_bounty_blocks": [
            {"rule": "known_patched_control", "reason": "known post-hoc Proof-of-Patch issue cannot count as fresh bounty evidence"}
        ],
        "notes": [
            "Issue is the confirmed case_pc_0002 Proof-of-Patch regression candidate.",
            "It is not a duplicate of the two killed batch candidates because they tested requestRedeem/requestRedeemWithPermit paths.",
            "Feedback memory contains prior post-hoc confirmed/rejected entries for this vertical-slice workflow." if memory_hits else "No matching feedback memory entry found.",
        ],
        "same_root_cause_candidates": same_root,
        "memory_hit_count": len(memory_hits),
        **safety_metadata(),
    }
    return write_json(closure_path(root, candidate_id, "duplicate_review.json"), payload)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Review duplicate and known-issue status")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--candidate", default=CONFIRMED_CANDIDATE_ID)
    args = p.parse_args(argv)
    result = review_duplicate_known_issue(Path(args.root), candidate_id=args.candidate)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
