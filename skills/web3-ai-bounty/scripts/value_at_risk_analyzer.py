#!/usr/bin/env python3
"""Quantify PoC-local value-at-risk for the confirmed post-hoc regression."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT
from report_ready_closure_utils import CONFIRMED_CANDIDATE_ID, closure_path, exact_poc_amounts, load_evidence, load_result, safety_metadata, write_json


def analyze_value_at_risk(root: Path = PUBLIC_ROOT, *, candidate_id: str = CONFIRMED_CANDIDATE_ID) -> dict[str, Any]:
    evidence = load_evidence(root, candidate_id)
    result = load_result(root, candidate_id)
    amounts = exact_poc_amounts(root)
    blocks: list[dict[str, str]] = []
    asset = evidence.get("affected_asset")
    if not asset:
        blocks.append({"rule": "missing_asset", "reason": "affected asset is required for value-at-risk"})
    if not amounts.get("currency_amount_requested") or not amounts.get("vulnerable_tranche_tokens_requested"):
        blocks.append({"rule": "missing_amount", "reason": "PoC amount could not be extracted"})
    if result.get("result") != "POC_PASS_CONFIRMS_HYPOTHESIS":
        blocks.append({"rule": "poc_not_confirmed", "reason": "value-at-risk requires confirmed PoC result"})
    payload = {
        "candidate_id": candidate_id,
        "impact_class": "fund_freeze" if not blocks else "unclear",
        "attacker_profit": False,
        "victim_loss_or_freeze": not blocks,
        "protocol_loss": False,
        "asset": asset or "unknown",
        "amount_in_poc": amounts,
        "amount_quantified_from_poc": not blocks,
        "can_scale_beyond_test_amount": "conditional",
        "scalability_assumption": "The arithmetic mismatch scales with orderbook maxDeposit/maxMint and rounded-down deposit price, but live deployment value-at-risk is not proven by local patched-control artifacts.",
        "impact_mechanism": "vulnerable processing calculates more tranche tokens than escrowed maxMint, causing the transfer to revert and leaving processing frozen for the user order",
        "economic_proof_status": "PARTIAL" if not blocks else "MISSING",
        "economic_blocks": blocks,
        "limitations": [
            "no attacker profit is demonstrated",
            "no live deployment balances or USD value were used",
            "duration and admin/operator recovery are not fully proven from local artifacts",
            "evidence is post-hoc patched-control regression only",
        ],
        "counts_toward_readiness": False,
        **safety_metadata(),
    }
    return write_json(closure_path(root, candidate_id, "value_at_risk_analysis.json"), payload)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Analyze value-at-risk for confirmed PoC")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--candidate", default=CONFIRMED_CANDIDATE_ID)
    args = p.parse_args(argv)
    result = analyze_value_at_risk(Path(args.root), candidate_id=args.candidate)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
