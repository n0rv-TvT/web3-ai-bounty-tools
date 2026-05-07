#!/usr/bin/env python3
"""Severity calibration for the confirmed post-hoc regression."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT
from economic_impact_calibrator import calibrate_economic_impact
from report_ready_closure_utils import CONFIRMED_CANDIDATE_ID, closure_path, load_evidence, load_json, safety_metadata, write_json
from value_at_risk_analyzer import analyze_value_at_risk


def calibrate_severity(root: Path = PUBLIC_ROOT, *, candidate_id: str = CONFIRMED_CANDIDATE_ID) -> dict[str, Any]:
    evidence = load_evidence(root, candidate_id)
    var = load_json(closure_path(root, candidate_id, "value_at_risk_analysis.json"), {}) or analyze_value_at_risk(root, candidate_id=candidate_id)
    econ = load_json(closure_path(root, candidate_id, "economic_proof.json"), {}) or calibrate_economic_impact(root, candidate_id=candidate_id)
    blocks: list[dict[str, str]] = []
    if not var.get("impact_class") or var.get("impact_class") == "unclear":
        blocks.append({"rule": "missing_impact", "reason": "severity requires an impact class"})
    if not evidence.get("likelihood"):
        blocks.append({"rule": "missing_likelihood", "reason": "severity requires likelihood"})
    if not var.get("amount_in_poc"):
        blocks.append({"rule": "missing_value_at_risk", "reason": "severity requires PoC amount or explicit limitation"})
    if econ.get("attacker_profit") is True:
        recommended = "High"
    elif var.get("impact_class") == "fund_freeze" and var.get("amount_quantified_from_poc"):
        recommended = "Medium"
    elif var.get("impact_class") == "fund_freeze":
        recommended = "Low"
    else:
        recommended = "Informational"
    payload = {
        "candidate_id": candidate_id,
        "recommended_severity": recommended if not blocks else "Informational",
        "impact": "conditional fund/accounting freeze in the local post-hoc deposit-processing path; no attacker profit and no USD value proven",
        "likelihood": evidence.get("likelihood") or "unknown",
        "preconditions": evidence.get("preconditions") or [],
        "attacker_capability": evidence.get("attacker_capability") or "normal external caller through liquidity-pool processing path",
        "severity_rationale": "Medium is appropriate for post-hoc regression evidence because the PoC proves a processing freeze and exact token-unit mismatch, but no theft, insolvency, live USD value, permanence, or fresh bounty scope is proven.",
        "severity_blocks": blocks,
        "framework": {
            "critical": "direct theft, permanent substantial freeze, insolvency, or governance takeover",
            "high": "major freeze or serious accounting corruption with strong live value-at-risk",
            "medium": "meaningful conditional fund freeze/accounting error or important invariant violation",
            "low": "minor edge case or low-value freeze",
            "informational": "weak or non-security issue",
        },
        "counts_toward_readiness": False,
        **safety_metadata(),
    }
    return write_json(closure_path(root, candidate_id, "severity_calibration.json"), payload)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Calibrate severity for confirmed PoC")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--candidate", default=CONFIRMED_CANDIDATE_ID)
    args = p.parse_args(argv)
    result = calibrate_severity(Path(args.root), candidate_id=args.candidate)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
