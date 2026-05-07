#!/usr/bin/env python3
"""Diagnose why a confirmed vertical-slice PoC is not report-ready."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT
from evidence_package_validator import validate_candidate


def load_json(path: Path, default: dict[str, Any] | None = None) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace")) if path.exists() else (default or {})


def safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_") or "candidate"


def candidate_matches(payload: dict[str, Any], candidate_id: str) -> bool:
    payload_candidate = payload.get("candidate_id")
    return not payload_candidate or payload_candidate == candidate_id


def candidate_result(root: Path, candidate_id: str) -> dict[str, Any]:
    specific = load_json(root / "scoring" / f"poc_vertical_slice_{safe_id(candidate_id)}_result.json", {})
    if specific and candidate_matches(specific, candidate_id):
        return specific
    batch = load_json(root / "scoring" / "poc_vertical_slice_batch_result.json", {})
    for row in batch.get("results", []):
        if row.get("candidate_id") == candidate_id:
            return row
    generic = load_json(root / "scoring" / "poc_vertical_slice_result.json", {})
    if generic and candidate_matches(generic, candidate_id):
        return generic
    package_specific = load_json(root / "scoring" / f"poc_vertical_slice_{safe_id(candidate_id)}_evidence_package.json", {})
    if package_specific and candidate_matches(package_specific, candidate_id):
        return {"result": package_specific.get("poc_result")}
    package_generic = load_json(root / "scoring" / "poc_vertical_slice_evidence_package.json", {})
    if package_generic and candidate_matches(package_generic, candidate_id):
        return {"result": package_generic.get("poc_result")}
    return {}


def analyze(root: Path = PUBLIC_ROOT, *, candidate_id: str) -> dict[str, Any]:
    validator = validate_candidate(root, candidate_id=candidate_id)
    pipeline = load_json(root / "scoring" / "poc_vertical_slice_pipeline_result.json", {})
    linter = load_json(root / "scoring" / "poc_vertical_slice_linter_result.json", {})
    result = candidate_result(root, candidate_id)
    gates = [
        {
            "gate": "evidence_package_validator",
            "passed": validator.get("valid", False),
            "blocks": validator.get("blocks", []),
            "missing_fields": validator.get("missing_fields", []),
            "fix_required": "Fill missing evidence package fields" if not validator.get("valid") else "none",
            "should_be_report_ready_after_fix": False,
        },
        {
            "gate": "finding_state_machine",
            "passed": False,
            "blocks": [b for block in pipeline.get("blocks", []) if block.get("gate") == "state_machine" for b in block.get("details", [])],
            "missing_fields": [],
            "fix_required": "Provide required REPORT_READY fields and economic proof if financial impact is claimed",
            "should_be_report_ready_after_fix": False,
        },
        {
            "gate": "pipeline_enforcer",
            "passed": pipeline.get("final_status") == "REPORT_READY",
            "blocks": pipeline.get("blocks", []),
            "missing_fields": [],
            "fix_required": "Resolve schema/economic/state-machine blockers without weakening gates",
            "should_be_report_ready_after_fix": False,
        },
        {
            "gate": "report_linter",
            "passed": linter.get("status") == "LINTER_PASS",
            "blocks": linter.get("blocks", []),
            "missing_fields": [],
            "fix_required": "Create a full impact-first report draft only after validation gates pass",
            "should_be_report_ready_after_fix": False,
        },
        {
            "gate": "economic_modeler",
            "passed": False,
            "blocks": [{"rule": "missing_economic_proof", "reason": "financial/fund-freeze impact needs economic proof or explicit non-financial scoping"}],
            "missing_fields": ["economic_proof"],
            "fix_required": "Generate a real economic proof task; do not fake proof",
            "should_be_report_ready_after_fix": False,
        },
        {
            "gate": "duplicate_root_cause_checker",
            "passed": False,
            "blocks": [{"rule": "not_checked", "reason": "duplicates/intended behavior not checked in this post-hoc workflow"}],
            "missing_fields": ["duplicate_check", "intended_behavior_check"],
            "fix_required": "Run duplicate/root-cause and intended-behavior review before report promotion",
            "should_be_report_ready_after_fix": False,
        },
        {
            "gate": "severity_calibrator",
            "passed": False,
            "blocks": [{"rule": "missing_program_scope_severity", "reason": "post-hoc control has no live scope/value calibration"}],
            "missing_fields": ["severity", "scope", "value_at_risk"],
            "fix_required": "Calibrate severity against in-scope impact and value-at-risk",
            "should_be_report_ready_after_fix": False,
        },
    ]
    final = {
        "status": "PASS",
        "candidate_id": candidate_id,
        "poc_result": result.get("result"),
        "report_ready": False,
        "primary_blocker": "missing economic proof, duplicate/intended-behavior review, severity calibration, and report draft despite executed post-hoc PoC",
        "gates": gates,
        "allowed_outcome": "BLOCKED_MISSING_ECONOMIC_PROOF",
        "production_readiness_changed": False,
    }
    json_path = root / "scoring" / "report_ready_blocker_analysis.json"
    json_path.write_text(json.dumps(final, indent=2) + "\n")
    md = ["# Report-Ready Blocker Analysis", "", f"Candidate: `{candidate_id}`", "", f"Primary blocker: {final['primary_blocker']}", "", "| Gate | Passed? | Required Fix |", "|---|---:|---|"]
    for gate in gates:
        md.append(f"| {gate['gate']} | {gate['passed']} | {gate['fix_required']} |")
    (root / "scoring" / "report_ready_blocker_analysis.md").write_text("\n".join(md) + "\n")
    return final


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Analyze report-ready blockers for vertical-slice evidence")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--candidate", required=True)
    args = p.parse_args(argv)
    result = analyze(Path(args.root), candidate_id=args.candidate)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
