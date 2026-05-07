#!/usr/bin/env python3
"""Draft a clearly labelled post-hoc regression report for the confirmed PoC."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from final_evidence_package_builder import build_final_package
from frozen_output_loader import PUBLIC_ROOT
from report_ready_closure_utils import CONFIRMED_CANDIDATE_ID, closure_path, load_json, safety_metadata, write_json


REQUIRED_REPORT_SECTIONS = [
    "Title",
    "Severity",
    "Status",
    "Scope note",
    "Affected contract/function",
    "Summary",
    "Root cause",
    "Preconditions",
    "Attack scenario",
    "Impact",
    "Likelihood",
    "Proof of Concept",
    "Patch regression result",
    "Recommended remediation",
    "Limitations",
    "Why this is post-hoc regression evidence only",
]


def build_report_markdown(package: dict) -> str:
    var = package.get("value_at_risk") or {}
    amounts = var.get("amount_in_poc") or {}
    econ = package.get("economic_proof") or {}
    severity = package.get("severity") or "Medium"
    title = "Rounding in InvestmentManager.processDeposit can freeze post-epoch deposit processing"
    return f"""# {title}

## Title
{title}

## Severity
Severity: {severity}

This severity is calibrated for post-hoc regression evidence. It is not a fresh bounty severity because live scope, USD value, duration, and recovery paths are not proven.

## Status
REPORT_READY_POSTHOC_REGRESSION. Normal bounty report-ready status is false.

## Scope note
The affected local patched-control files are `{package.get('file')}` in pair `{package.get('pair_id')}`. This draft is post-hoc patched-control regression evidence only and does not claim production readiness or fresh bounty eligibility.

## Affected contract/function
File: {package.get('file')}
Contract: {package.get('contract')}
Function: {package.get('function')} lifecycle, with the confirmed revert in `processDeposit`.
Affected Asset: {package.get('affected_asset')}

## Summary
The PoC demonstrates that the vulnerable deposit-processing path calculates more tranche tokens than the escrowed `maxMint` amount for a rounded-down price. The transfer from escrow then reverts, leaving the processed deposit path frozen for the user order. The patched control clamps the calculated tranche-token amount to `maxMint` and the same step completes.

## Root cause
`processDeposit` uses a rounded tranche-token calculation without clamping the result to `orderbook[user][liquidityPool].maxMint` before decreasing limits and transferring escrowed tranche tokens.

## Preconditions
{chr(10).join(f'- {item}' for item in (package.get('preconditions') or []))}

Additional PoC precondition: an executed deposit order has `maxDeposit={amounts.get('currency_amount_requested')}` and `maxMint={amounts.get('escrowed_tranche_tokens')}`.

## Attack scenario
{chr(10).join(f'{idx + 1}. {item}' for idx, item in enumerate(package.get('exploit_sequence') or []))}

## Impact
Impact class: {var.get('impact_class')}
Attacker profit: {econ.get('attacker_profit')}
Victim loss or freeze: {var.get('victim_loss_or_freeze')}
Protocol loss: {var.get('protocol_loss')}
Value at risk: {json.dumps(amounts, sort_keys=True)}

This is a fund/accounting freeze, not theft. The PoC proves token-unit mismatch and failed processing; it does not prove attacker profit, USD loss, protocol insolvency, or live value at risk.

## Likelihood
{package.get('likelihood')}

The condition requires an executed order where the rounded-down deposit price makes the calculated tranche-token amount exceed escrowed `maxMint`.

## Proof of Concept
PoC path: `generated_pocs/case_pc_0002_vulnerable/POC_PREC_case_pc_0002_vulnerable_002/test/GeneratedPoC.t.sol`

Command:
```bash
{package.get('poc_command')}
```

Result: {package.get('poc_result')}

## Patch regression result
Vulnerable result: `PASS_ASSERTED_REVERT_FUND_FREEZE`.
Patched result: `{package.get('patched_regression_result')}`.
The patched path transfers exactly `maxMint={amounts.get('patched_tranche_tokens_transferred')}` and consumes deposit/mint limits exactly.

## Recommended remediation
{package.get('recommended_fix')}

## Limitations
{chr(10).join(f'- {item}' for item in (package.get('limitations') or []))}
- Economic proof status: {econ.get('economic_proof_status')}; token-unit impact is quantified, live USD impact is not.
- Known issue status: {package.get('duplicate_known_issue_status')}.
- Counts toward readiness: {package.get('counts_toward_readiness')}.

## Why this is post-hoc regression evidence only
This report is generated from a known patched-control Proof-of-Patch pair after the freeze. It is useful as regression evidence for the evaluation harness, but it is not fresh independent bounty evidence and does not change production readiness.
"""


def build_report_draft(root: Path = PUBLIC_ROOT, *, candidate_id: str = CONFIRMED_CANDIDATE_ID) -> dict:
    package_path = closure_path(root, candidate_id, "final_evidence_package.json")
    package = load_json(package_path, {}) or build_final_package(root, candidate_id=candidate_id)
    markdown = build_report_markdown(package)
    md_path = closure_path(root, candidate_id, "report_draft.md")
    md_path.write_text(markdown)
    result = {
        "status": "PASS",
        "candidate_id": candidate_id,
        "report_draft": str(md_path.relative_to(root)),
        "sections": REQUIRED_REPORT_SECTIONS,
        "post_hoc_regression_only": True,
        "report_ready_created": False,
        **safety_metadata(),
    }
    return write_json(closure_path(root, candidate_id, "report_draft_result.json"), result)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Build post-hoc regression report draft")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--candidate", default=CONFIRMED_CANDIDATE_ID)
    args = p.parse_args(argv)
    result = build_report_draft(Path(args.root), candidate_id=args.candidate)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
