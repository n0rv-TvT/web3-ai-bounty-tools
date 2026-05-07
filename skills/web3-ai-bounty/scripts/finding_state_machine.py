#!/usr/bin/env python3
"""Strict finding lifecycle enforcement for Web3 audit leads."""

from __future__ import annotations

import argparse
import json
from copy import deepcopy
from pathlib import Path
from typing import Any


STATES = {
    "RAW_LEAD",
    "SCANNER_LEAD",
    "MANUAL_LEAD",
    "HYPOTHESIS",
    "NEEDS_CONTEXT",
    "CHAIN_REQUIRED",
    "POC_REQUIRED",
    "ECONOMIC_PROOF_REQUIRED",
    "FALSE_POSITIVE",
    "DUPLICATE",
    "KILLED",
    "CONFIRMED",
    "REPORT_READY",
}

TERMINAL_STATES = {"FALSE_POSITIVE", "DUPLICATE", "KILLED", "REPORT_READY"}
FINANCIAL_IMPACTS = {"stolen-funds", "frozen-funds", "bad-debt", "insolvency", "governance-takeover"}
REPORT_READY_REQUIRED_FIELDS = [
    "file_path",
    "contract",
    "function",
    "code_path",
    "preconditions",
    "attacker_capabilities",
    "affected_asset",
    "exploit_scenario",
    "impact",
    "likelihood",
    "severity_rationale",
    "poc",
    "fix",
    "confidence",
]


def create_scanner_lead(scanner_output: dict[str, Any]) -> dict[str, Any]:
    """Scanner output can only create SCANNER_LEAD."""

    lead = dict(scanner_output)
    lead["state"] = "SCANNER_LEAD"
    lead.setdefault("source", "scanner")
    return lead


def missing_quality_fields(finding: dict[str, Any]) -> list[str]:
    """Return required REPORT_READY fields that are absent or empty."""

    missing: list[str] = []
    for field in REPORT_READY_REQUIRED_FIELDS:
        value = finding.get(field)
        if value is None or value == "" or value == [] or value == {}:
            missing.append(field)
    return missing


def is_financial_finding(finding: dict[str, Any]) -> bool:
    impact = finding.get("impact")
    if isinstance(impact, dict):
        typ = str(impact.get("type") or "").lower()
    else:
        typ = str(finding.get("impact_type") or impact or "").lower()
    return typ in FINANCIAL_IMPACTS or any(term in typ for term in ["fund", "debt", "insolv"])


def has_valid_economic_proof(finding: dict[str, Any]) -> bool:
    proof = finding.get("economic_proof") or {}
    return isinstance(proof, dict) and proof.get("verdict") == "REPORT_READY" and proof.get("schema_valid") is True


def transition_blocks(finding: dict[str, Any], target_state: str) -> list[dict[str, str]]:
    """Return blockers for a proposed state transition."""

    if target_state not in STATES:
        return [{"rule": "invalid_state", "reason": f"unknown target state {target_state}"}]
    current = str(finding.get("state") or "RAW_LEAD")
    blocks: list[dict[str, str]] = []
    if current in TERMINAL_STATES and current != target_state:
        blocks.append({"rule": "terminal_state", "reason": f"{current} is terminal"})
    if current == "SCANNER_LEAD" and target_state == "REPORT_READY":
        blocks.append({"rule": "scanner_direct_report", "reason": "SCANNER_LEAD cannot become REPORT_READY directly"})
    if target_state == "REPORT_READY":
        if finding.get("duplicate_of") or finding.get("duplicate_root_cause") is True:
            blocks.append({"rule": "duplicate", "reason": "duplicate/root-cause findings must be merged or killed"})
        for field in missing_quality_fields(finding):
            blocks.append({"rule": "missing_evidence", "reason": f"missing required field: {field}"})
        if is_financial_finding(finding) and not has_valid_economic_proof(finding):
            blocks.append({"rule": "missing_economic_proof", "reason": "financial-impact findings require economic proof"})
        if not (finding.get("poc") or {}).get("path"):
            blocks.append({"rule": "missing_poc_artifact", "reason": "REPORT_READY requires PoC artifact path"})
    return blocks


def can_transition(finding: dict[str, Any], target_state: str) -> dict[str, Any]:
    blocks = transition_blocks(finding, target_state)
    return {"allowed": not blocks, "from": finding.get("state", "RAW_LEAD"), "to": target_state, "blocks": blocks}


def promote(finding: dict[str, Any], target_state: str) -> dict[str, Any]:
    """Return promoted finding copy or fail closed with blockers."""

    result = can_transition(finding, target_state)
    if not result["allowed"]:
        raise SystemExit(json.dumps(result, indent=2))
    out = deepcopy(finding)
    out["state"] = target_state
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Validate Web3 finding state transitions")
    p.add_argument("finding_json")
    p.add_argument("target_state")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    finding = json.loads(Path(args.finding_json).read_text(errors="replace"))
    print(json.dumps(can_transition(finding, args.target_state), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
