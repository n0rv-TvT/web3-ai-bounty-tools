#!/usr/bin/env python3
"""Review whether the confirmed behavior is likely unintended."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT
from report_ready_closure_utils import CONFIRMED_CANDIDATE_ID, closure_path, load_result, patched_source_path, read_text, safety_metadata, vulnerable_source_path, write_json


def review_intended_behavior(root: Path = PUBLIC_ROOT, *, candidate_id: str = CONFIRMED_CANDIDATE_ID) -> dict[str, Any]:
    vuln_text = read_text(vulnerable_source_path(root))
    patched_text = read_text(patched_source_path(root))
    result = load_result(root, candidate_id)
    evidence: list[str] = []
    if "tranche tokens can be transferred to user's wallet" in vuln_text:
        evidence.append("NatSpec for processDeposit states tranche tokens can be transferred to the user's wallet after epoch execution.")
    if result.get("vulnerable_test_status") == "PASS_ASSERTED_REVERT_FUND_FREEZE":
        evidence.append("Confirmed PoC shows the vulnerable full-deposit processing action reverts and leaves escrow/user share state unchanged.")
    if result.get("patched_test_status") == "PASS_ASSERTED_CLAMP_ACCOUNTING_PRESERVED":
        evidence.append("Patched-control result shows the same step succeeds when the calculated tranche token amount is clamped to maxMint.")
    if "rounding errors" in patched_text and "maxMint" in patched_text:
        evidence.append("Patched source comments/code identify the clamp as preventing rounding errors during share transfer from escrow to investor.")
    blocks: list[dict[str, str]] = []
    if not evidence:
        blocks.append({"rule": "missing_intended_behavior_evidence", "reason": "requires source, PoC, or patch-behavior evidence"})
    likely_unintended = len(evidence) >= 3
    if not likely_unintended:
        blocks.append({"rule": "human_review_required", "reason": "insufficient evidence to classify behavior as unintended"})
    payload = {
        "candidate_id": candidate_id,
        "likely_unintended": likely_unintended,
        "evidence": evidence,
        "checks": {
            "contradicts_comments_or_invariants": any("NatSpec" in item for item in evidence),
            "patched_version_removes_behavior": any("Patched-control" in item for item in evidence),
            "could_be_intentional_revert_failsafe": False,
            "depends_on_unrealistic_test_assumptions": "unknown; local harness isolates arithmetic/orderbook boundary",
            "normal_protocol_operation_allows_state": "executed order with maxDeposit/maxMint is described by processDeposit comments",
            "admin_or_operator_recovery_proven": False,
        },
        "intended_behavior_blocks": blocks,
        "requires_human_review": True,
        "human_review_reason": "Patch behavior is strong regression evidence but not absolute proof of bounty-program intended behavior.",
        "counts_toward_readiness": False,
        **safety_metadata(),
    }
    return write_json(closure_path(root, candidate_id, "intended_behavior_review.json"), payload)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Review intended behavior for confirmed PoC")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--candidate", default=CONFIRMED_CANDIDATE_ID)
    args = p.parse_args(argv)
    result = review_intended_behavior(Path(args.root), candidate_id=args.candidate)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
