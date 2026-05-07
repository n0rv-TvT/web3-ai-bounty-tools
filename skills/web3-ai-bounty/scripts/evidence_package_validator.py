#!/usr/bin/env python3
"""Validate post-hoc PoC vertical-slice evidence packages."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT
from report_ready_closure_utils import closure_path

REQUIRED_FIELDS = [
    "candidate_id",
    "pair_id",
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
    "severity_rationale",
    "poc_command",
    "poc_result",
    "patched_regression_result",
    "recommended_fix",
    "confidence",
    "limitations",
]

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


def safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_") or "candidate"


def package_path(root: Path, candidate_id: str) -> Path:
    if candidate_id.startswith("EXPECTED-ALIGNED-"):
        return root / "scoring" / "fresh_v6_expected_aligned_execution" / "expected_aligned_evidence_package.json"
    if candidate_id.startswith("REPAIR-POC-"):
        return root / "scoring" / "repaired_candidate_execution" / "repair_candidate_evidence_package.json"
    specific = root / "scoring" / f"poc_vertical_slice_{safe_id(candidate_id)}_evidence_package.json"
    if specific.exists():
        return specific
    return root / "scoring" / "poc_vertical_slice_evidence_package.json"


def final_package_path(root: Path, candidate_id: str) -> Path:
    if candidate_id.startswith("EXPECTED-ALIGNED-"):
        return root / "scoring" / "fresh_v6_expected_aligned_execution" / "expected_aligned_evidence_package.json"
    if candidate_id.startswith("REPAIR-POC-"):
        return root / "scoring" / "repaired_candidate_execution" / "repair_candidate_final_evidence_package.json"
    return closure_path(root, candidate_id, "final_evidence_package.json")


def load_package(root: Path, candidate_id: str) -> dict[str, Any]:
    path = package_path(root, candidate_id)
    return json.loads(path.read_text(errors="replace")) if path.exists() else {}


def empty(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def needs_economic_proof(package: dict[str, Any]) -> bool:
    text = " ".join(str(package.get(k, "")) for k in ["impact", "severity_rationale", "affected_asset"]).lower()
    if package.get("economic_proof"):
        return False
    return any(token in text for token in ["stolen", "bad debt", "profit", "usd", "insolvency"])


def validate_package(package: dict[str, Any]) -> dict[str, Any]:
    missing = [field for field in REQUIRED_FIELDS if empty(package.get(field))]
    blocks = []
    for field in missing:
        blocks.append({"rule": "missing_field", "field": field, "reason": f"missing or empty required field: {field}"})
    if needs_economic_proof(package):
        blocks.append({"rule": "missing_economic_proof", "field": "economic_proof", "reason": "financial-impact claim requires economic proof"})
    if package.get("poc_result") == "POC_PASS_CONFIRMS_HYPOTHESIS" and package.get("report_ready") is True:
        blocks.append({"rule": "auto_report_ready", "reason": "confirmed PoC must not automatically mark report_ready"})
    status = "PASS" if not blocks else classify_blocks(blocks)
    return {"status": status, "valid": not blocks, "missing_fields": missing, "blocks": blocks, "report_ready_created": False, "production_readiness_changed": False}


def validate_final_package(package: dict[str, Any]) -> dict[str, Any]:
    missing = [field for field in FINAL_REQUIRED_FIELDS if empty(package.get(field))]
    blocks = [{"rule": "missing_field", "field": field, "reason": f"missing or empty required field: {field}"} for field in missing]
    if package.get("status") != "CONFIRMED_POSTHOC_REGRESSION":
        blocks.append({"rule": "invalid_status", "field": "status", "reason": "final package must be CONFIRMED_POSTHOC_REGRESSION"})
    if package.get("poc_result") != "POC_PASS_CONFIRMS_HYPOTHESIS":
        blocks.append({"rule": "poc_not_confirmed", "field": "poc_result", "reason": "final package requires confirmed PoC"})
    if package.get("duplicate_known_issue_status") == "KNOWN_PATCHED_CONTROL" and package.get("counts_toward_readiness") is not False:
        blocks.append({"rule": "known_issue_counts_toward_readiness", "field": "counts_toward_readiness", "reason": "known patched-control issue must not count toward readiness"})
    status = "PASS" if not blocks else classify_blocks(blocks)
    return {"status": status, "valid": not blocks, "missing_fields": missing, "blocks": blocks, "report_ready_created": False, "production_readiness_changed": False}


REPAIRED_FINAL_REQUIRED_FIELDS = [
    "candidate_id",
    "status",
    "file",
    "contract",
    "function",
    "vulnerable_code_path",
    "affected_asset",
    "exploit_sequence",
    "impact",
    "poc_command",
    "poc_result",
    "recommended_fix",
    "report_key",
    "normal_bounty_report_ready",
    "counts_toward_readiness",
]


def validate_repaired_final_package(package: dict[str, Any]) -> dict[str, Any]:
    missing = [field for field in REPAIRED_FINAL_REQUIRED_FIELDS if empty(package.get(field))]
    blocks = [{"rule": "missing_field", "field": field, "reason": f"missing or empty repaired final evidence field: {field}"} for field in missing]
    if package.get("status") != "REPORT_READY_POSTHOC_SPENT_HOLDOUT":
        blocks.append({"rule": "invalid_status", "field": "status", "reason": "repaired final package must remain post-hoc spent-holdout only"})
    if package.get("poc_result") != "POC_PASS_CONFIRMS_HYPOTHESIS":
        blocks.append({"rule": "poc_not_confirmed", "field": "poc_result", "reason": "repaired final package requires confirmed PoC"})
    if package.get("normal_bounty_report_ready") is not False or package.get("counts_toward_readiness") is not False:
        blocks.append({"rule": "spent_holdout_readiness_guard", "reason": "spent holdout evidence must not be normal report-ready or count toward readiness"})
    return {"status": "PASS" if not blocks else "BLOCKED_REPAIRED_FINAL_PACKAGE", "valid": not blocks, "missing_fields": missing, "blocks": blocks, "report_ready_created": False, "production_readiness_changed": False, "counts_toward_readiness": False}


EXPECTED_ALIGNED_FINAL_REQUIRED_FIELDS = [
    "candidate_id",
    "case_id",
    "expected_finding_id",
    "status",
    "file",
    "contract",
    "function",
    "vulnerable_code_path",
    "preconditions",
    "normal_user_or_victim_action",
    "attacker_capability",
    "affected_asset",
    "exploit_sequence",
    "impact",
    "likelihood",
    "severity_rationale",
    "poc_command",
    "poc_result",
    "recommended_fix",
    "known_issue_status",
    "normal_bounty_report_ready",
    "counts_toward_readiness",
]


def validate_expected_aligned_final_package(package: dict[str, Any]) -> dict[str, Any]:
    missing = [field for field in EXPECTED_ALIGNED_FINAL_REQUIRED_FIELDS if empty(package.get(field))]
    blocks = [{"rule": "missing_field", "field": field, "reason": f"missing or empty expected-aligned final evidence field: {field}"} for field in missing]
    if package.get("status") != "CONFIRMED_POSTHOC_EXPECTED_ALIGNED_SPENT_HOLDOUT":
        blocks.append({"rule": "invalid_status", "field": "status", "reason": "expected-aligned package must remain post-hoc spent-holdout confirmation only"})
    if package.get("poc_result") != "POC_PASS_CONFIRMS_EXPECTED_ALIGNED_HYPOTHESIS":
        blocks.append({"rule": "poc_not_confirmed", "field": "poc_result", "reason": "expected-aligned final package requires confirmed PoC"})
    if package.get("normal_bounty_report_ready") is not False or package.get("counts_toward_readiness") is not False:
        blocks.append({"rule": "spent_holdout_readiness_guard", "reason": "expected-aligned spent holdout must not be normal report-ready or count toward readiness"})
    return {"status": "PASS" if not blocks else "BLOCKED_EXPECTED_ALIGNED_FINAL_PACKAGE", "valid": not blocks, "missing_fields": missing, "blocks": blocks, "report_ready_created": False, "production_readiness_changed": False, "counts_toward_readiness": False}


def classify_blocks(blocks: list[dict[str, Any]]) -> str:
    if any(b.get("rule") == "missing_economic_proof" for b in blocks):
        return "BLOCKED_MISSING_ECONOMIC_PROOF"
    for field, status in [("severity_rationale", "BLOCKED_MISSING_SEVERITY_RATIONALE"), ("likelihood", "BLOCKED_MISSING_LIKELIHOOD"), ("recommended_fix", "BLOCKED_MISSING_REMEDIATION")]:
        if any(b.get("field") == field for b in blocks):
            return status
    return "BLOCKED_SCHEMA_MISMATCH"


def validate_candidate(root: Path = PUBLIC_ROOT, *, candidate_id: str) -> dict[str, Any]:
    path = package_path(root, candidate_id)
    package = load_package(root, candidate_id)
    result = validate_package(package)
    result.update({"candidate_id": candidate_id, "evidence_package": str(path.relative_to(root)) if path.exists() else "missing"})
    out = root / "scoring" / f"poc_vertical_slice_{safe_id(candidate_id)}_evidence_validation.json"
    out.write_text(json.dumps(result, indent=2) + "\n")
    if candidate_id == "POC-PREC-case_pc_0002-vulnerable-002":
        (root / "scoring" / "poc_vertical_slice_evidence_validation.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def validate_final_candidate(root: Path = PUBLIC_ROOT, *, candidate_id: str) -> dict[str, Any]:
    path = final_package_path(root, candidate_id)
    package = json.loads(path.read_text(errors="replace")) if path.exists() else {}
    if candidate_id.startswith("EXPECTED-ALIGNED-"):
        result = validate_expected_aligned_final_package(package)
    elif candidate_id.startswith("REPAIR-POC-"):
        result = validate_repaired_final_package(package)
    else:
        result = validate_final_package(package)
    result.update({"candidate_id": candidate_id, "evidence_package": str(path.relative_to(root)) if path.exists() else "missing", "final": True})
    if candidate_id.startswith("EXPECTED-ALIGNED-"):
        out = root / "scoring" / "fresh_v6_expected_aligned_execution" / "expected_aligned_final_evidence_validation.json"
    elif candidate_id.startswith("REPAIR-POC-"):
        out = root / "scoring" / "repaired_candidate_execution" / "repair_candidate_final_evidence_validation.json"
    else:
        out = closure_path(root, candidate_id, "final_evidence_validation.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Validate vertical-slice evidence package")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--candidate", required=True)
    p.add_argument("--final", action="store_true")
    args = p.parse_args(argv)
    result = validate_final_candidate(Path(args.root), candidate_id=args.candidate) if args.final else validate_candidate(Path(args.root), candidate_id=args.candidate)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
