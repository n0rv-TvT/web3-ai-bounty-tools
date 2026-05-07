#!/usr/bin/env python3
"""Build economic proof for the confirmed post-hoc regression without inventing live value."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT
from report_ready_closure_utils import CONFIRMED_CANDIDATE_ID, closure_path, load_json, safety_metadata, write_json
from value_at_risk_analyzer import analyze_value_at_risk


def calibrate_economic_impact(root: Path = PUBLIC_ROOT, *, candidate_id: str = CONFIRMED_CANDIDATE_ID) -> dict[str, Any]:
    var_path = closure_path(root, candidate_id, "value_at_risk_analysis.json")
    var = load_json(var_path, {}) or analyze_value_at_risk(root, candidate_id=candidate_id)
    blocks: list[dict[str, str]] = []
    if not var.get("asset") or var.get("asset") == "unknown":
        blocks.append({"rule": "missing_asset", "reason": "economic proof requires affected asset"})
    if not var.get("amount_in_poc"):
        blocks.append({"rule": "missing_amount", "reason": "economic proof requires PoC amount or explicit limitation"})
    if var.get("impact_class") != "fund_freeze":
        blocks.append({"rule": "unsupported_impact_class", "reason": "only fund_freeze was proven for this candidate"})
    payload = {
        "candidate_id": candidate_id,
        "schema_valid": not blocks,
        "verdict": "REPORT_READY_POSTHOC_REGRESSION" if not blocks else "BLOCKED_MISSING_ECONOMIC_PROOF",
        "economic_proof_status": "PARTIAL" if not blocks else "MISSING",
        "impact_class": var.get("impact_class"),
        "attacker_profit": False,
        "theft_claimed": False,
        "victim_loss_or_freeze": bool(var.get("victim_loss_or_freeze")),
        "protocol_loss": False,
        "asset": var.get("asset"),
        "amount_in_poc": var.get("amount_in_poc"),
        "impact": {
            "type": "frozen-funds",
            "asset": var.get("asset"),
            "frozen_amount_in_poc": var.get("amount_in_poc"),
            "protocol_loss_usd": "0",
            "bad_debt_usd": "0",
            "currency": "token-units",
            "amount": str((var.get("amount_in_poc") or {}).get("currency_amount_requested", "")),
            "assumption_source": "local Foundry vertical-slice PoC constants",
            "calculation_method": "compare vulnerable requested tranche tokens with escrowed/patched maxMint amount",
        },
        "profitability": {"net_profit_usd": "0", "attacker_profit": False},
        "value_at_risk_limitations": var.get("limitations", []),
        "blocks": blocks,
        "limitations": [
            "PoC quantifies token-unit mismatch but not USD value",
            "normal fresh bounty economic proof remains incomplete without live scope/value-at-risk",
            "this is not a theft finding because attacker profit is false",
        ],
        "counts_toward_readiness": False,
        **safety_metadata(),
    }
    return write_json(closure_path(root, candidate_id, "economic_proof.json"), payload)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Calibrate economic impact for confirmed PoC")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--candidate", default=CONFIRMED_CANDIDATE_ID)
    args = p.parse_args(argv)
    result = calibrate_economic_impact(Path(args.root), candidate_id=args.candidate)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
