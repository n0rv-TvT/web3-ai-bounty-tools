#!/usr/bin/env python3
"""Build the final report-readiness closure evidence package."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from duplicate_known_issue_reviewer import review_duplicate_known_issue
from economic_impact_calibrator import calibrate_economic_impact
from frozen_output_loader import PUBLIC_ROOT
from intended_behavior_reviewer import review_intended_behavior
from report_ready_closure_utils import CONFIRMED_CANDIDATE_ID, closure_path, load_evidence, load_json, load_result, required_missing, safety_metadata, write_json
from scope_review import review_scope
from severity_calibrator import calibrate_severity
from value_at_risk_analyzer import analyze_value_at_risk


FINAL_REQUIRED_FIELDS = [
    "candidate_id",
    "pair_id",
    "status",
    "file",
    "contract",
    "function",
    "vulnerable_code_path",
    "preconditions",
    "attacker_capability",
    "affected_asset",
    "exploit_sequence",
    "impact",
    "likelihood",
    "severity",
    "severity_rationale",
    "value_at_risk",
    "economic_proof",
    "poc_command",
    "poc_result",
    "patched_regression_result",
    "recommended_fix",
    "duplicate_known_issue_status",
    "intended_behavior_review",
    "limitations",
    "confidence",
    "counts_toward_readiness",
]


def validate_final_package(package: dict[str, Any]) -> dict[str, Any]:
    missing = required_missing(package, FINAL_REQUIRED_FIELDS)
    blocks = [{"rule": "missing_field", "field": field, "reason": f"missing or empty required field: {field}"} for field in missing]
    if package.get("poc_result") != "POC_PASS_CONFIRMS_HYPOTHESIS":
        blocks.append({"rule": "poc_not_confirmed", "reason": "final evidence package requires confirmed PoC"})
    if package.get("duplicate_known_issue_status") == "KNOWN_PATCHED_CONTROL" and package.get("counts_toward_readiness") is not False:
        blocks.append({"rule": "known_issue_readiness_flag", "reason": "known patched-control issue must not count toward readiness"})
    return {"status": "PASS" if not blocks else "BLOCKED_SCHEMA_OR_PIPELINE_MISMATCH", "valid": not blocks, "missing_fields": missing, "blocks": blocks}


def build_final_package(root: Path = PUBLIC_ROOT, *, candidate_id: str = CONFIRMED_CANDIDATE_ID) -> dict[str, Any]:
    evidence = load_evidence(root, candidate_id)
    result = load_result(root, candidate_id)
    scope = load_json(closure_path(root, candidate_id, "scope_review.json"), {}) or review_scope(root, candidate_id=candidate_id)
    var = load_json(closure_path(root, candidate_id, "value_at_risk_analysis.json"), {}) or analyze_value_at_risk(root, candidate_id=candidate_id)
    econ = load_json(closure_path(root, candidate_id, "economic_proof.json"), {}) or calibrate_economic_impact(root, candidate_id=candidate_id)
    sev = load_json(closure_path(root, candidate_id, "severity_calibration.json"), {}) or calibrate_severity(root, candidate_id=candidate_id)
    intended = load_json(closure_path(root, candidate_id, "intended_behavior_review.json"), {}) or review_intended_behavior(root, candidate_id=candidate_id)
    dup = load_json(closure_path(root, candidate_id, "duplicate_review.json"), {}) or review_duplicate_known_issue(root, candidate_id=candidate_id)
    package = {
        "candidate_id": candidate_id,
        "pair_id": evidence.get("pair_id"),
        "status": "CONFIRMED_POSTHOC_REGRESSION",
        "file": evidence.get("file"),
        "contract": evidence.get("contract"),
        "function": evidence.get("function"),
        "vulnerable_code_path": evidence.get("vulnerable_code_path"),
        "preconditions": evidence.get("preconditions"),
        "attacker_capability": evidence.get("attacker_capability"),
        "affected_asset": evidence.get("affected_asset"),
        "exploit_sequence": evidence.get("exploit_sequence"),
        "impact": "Fund/accounting freeze: vulnerable processing reverts when rounded calculation asks escrow to transfer more tranche tokens than maxMint.",
        "likelihood": evidence.get("likelihood"),
        "severity": sev.get("recommended_severity"),
        "severity_rationale": sev.get("severity_rationale"),
        "value_at_risk": var,
        "economic_proof": econ,
        "poc_command": evidence.get("poc_command"),
        "poc_result": result.get("result") or evidence.get("poc_result"),
        "patched_regression_result": result.get("patched_test_status") or evidence.get("patched_regression_result"),
        "recommended_fix": evidence.get("recommended_fix"),
        "duplicate_known_issue_status": dup.get("known_issue_status"),
        "intended_behavior_review": "likely_unintended" if intended.get("likely_unintended") else "unclear",
        "limitations": list(dict.fromkeys((evidence.get("limitations") or []) + (var.get("limitations") or []) + ["known patched-control Proof-of-Patch issue", "not fresh independent bounty evidence"])),
        "confidence": "medium",
        "counts_toward_readiness": False,
        "normal_bounty_report_ready": False,
        "scope_review": scope,
        "severity_calibration": sev,
        "duplicate_review": dup,
        "intended_behavior_details": intended,
        "report_ready_status": "REPORT_READY_POSTHOC_REGRESSION",
        **safety_metadata(),
    }
    validation = validate_final_package(package)
    package["validation_status"] = validation["status"]
    write_json(closure_path(root, candidate_id, "final_evidence_package.json"), package)
    write_json(closure_path(root, candidate_id, "final_evidence_validation.json"), {**validation, "candidate_id": candidate_id, "production_readiness_changed": False})
    return package


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Build final closure evidence package")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--candidate", default=CONFIRMED_CANDIDATE_ID)
    args = p.parse_args(argv)
    result = build_final_package(Path(args.root), candidate_id=args.candidate)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
