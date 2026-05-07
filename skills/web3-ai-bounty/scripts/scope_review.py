#!/usr/bin/env python3
"""Scope review for the single confirmed post-hoc vertical-slice PoC."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT
from report_ready_closure_utils import (
    CONFIRMED_CANDIDATE_ID,
    closure_path,
    load_evidence,
    load_result,
    patched_source_path,
    read_text,
    safety_metadata,
    vulnerable_source_path,
    write_json,
)


def review_scope(root: Path = PUBLIC_ROOT, *, candidate_id: str = CONFIRMED_CANDIDATE_ID) -> dict[str, Any]:
    evidence = load_evidence(root, candidate_id)
    result = load_result(root, candidate_id)
    vuln_text = read_text(vulnerable_source_path(root))
    patched_text = read_text(patched_source_path(root))
    contract_in_scope = evidence.get("contract") == "InvestmentManager" and "contract InvestmentManager" in vuln_text
    function_in_scope = evidence.get("function") == "requestDeposit" and "function requestDeposit" in vuln_text and "function processDeposit" in vuln_text
    asset_in_scope = "tranche" in str(evidence.get("affected_asset", "")).lower() and "escrow" in str(evidence.get("affected_asset", "")).lower()
    confirmed = result.get("result") == "POC_PASS_CONFIRMS_HYPOTHESIS"
    impact_type = "fund_freeze" if confirmed and "freeze" in str(evidence.get("impact", "")).lower() else "unclear"
    scope_blocks: list[dict[str, str]] = []
    if not contract_in_scope:
        scope_blocks.append({"rule": "contract_scope_unclear", "reason": "InvestmentManager source was not found in the local patched-control corpus"})
    if not function_in_scope:
        scope_blocks.append({"rule": "function_scope_unclear", "reason": "requestDeposit/processDeposit lifecycle was not found in local source"})
    if not asset_in_scope:
        scope_blocks.append({"rule": "asset_scope_unclear", "reason": "affected escrow/tranche-token asset is not established"})
    if impact_type == "unclear":
        scope_blocks.append({"rule": "impact_scope_unclear", "reason": "confirmed fund/accounting freeze impact was not established"})
    bounty_relevance = "in_scope" if not scope_blocks else "unclear"
    payload = {
        "candidate_id": candidate_id,
        "contract_in_scope": contract_in_scope,
        "function_in_scope": function_in_scope,
        "asset_in_scope": asset_in_scope,
        "impact_type": impact_type,
        "bounty_relevance": bounty_relevance,
        "scope_blocks": scope_blocks,
        "confidence": "medium" if not scope_blocks else "low",
        "scope_basis": "local patched-control regression scope only; no fresh live bounty scope was asserted",
        "post_hoc_regression_only": True,
        "fresh_bounty_scope_proven": False,
        "counts_toward_readiness": False,
        "evidence": [
            "InvestmentManager.sol exists in both case_pc_0002 vulnerable and patched local controls" if contract_in_scope else "InvestmentManager source missing",
            "requestDeposit lifecycle and processDeposit processing path are present in source" if function_in_scope else "requestDeposit/processDeposit path missing",
            "affected asset is escrowed tranche-token/deposit accounting" if asset_in_scope else "asset unclear",
            "patched-control PoC result confirms fund/accounting freeze behavior" if confirmed else "PoC result not confirmed",
            "patched source includes the clamp that preserves processing" if "_trancheTokenAmount > orderbook" in patched_text else "patched clamp not found",
        ],
        **safety_metadata(),
    }
    return write_json(closure_path(root, candidate_id, "scope_review.json"), payload)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Review confirmed PoC scope")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--candidate", default=CONFIRMED_CANDIDATE_ID)
    args = p.parse_args(argv)
    result = review_scope(Path(args.root), candidate_id=args.candidate)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
