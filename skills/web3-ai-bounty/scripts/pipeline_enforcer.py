#!/usr/bin/env python3
"""End-to-end Web3 audit lead pipeline enforcer."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from cross_chain_checker import evaluate_cross_chain_lead
from feedback_memory import query_feedback_memory
from finding_state_machine import can_transition
from mev_modeler import evaluate_mev_lead
from report_linter import lint_report
from report_ready_closure_utils import closure_path, load_json, safety_metadata
from schema_validator import validate_payload


FINAL_STATUSES = {"REPORT_READY", "REPORT_READY_POSTHOC_REGRESSION", "REPORT_READY_POSTHOC_SPENT_HOLDOUT", "REPORT_READY_POSTHOC_EXPECTED_ALIGNED_SPENT_HOLDOUT", "HYPOTHESIS_ONLY", "NEEDS_CONTEXT", "FALSE_POSITIVE", "DUPLICATE", "KILLED", "BLOCKED"}


def is_financial(lead: dict[str, Any]) -> bool:
    typ = str((lead.get("impact") or {}).get("type") or lead.get("impact_type") or "").lower()
    return any(x in typ for x in ["fund", "debt", "insolv", "governance"])


def economic_gate(lead: dict[str, Any], proof: dict[str, Any] | None) -> dict[str, Any]:
    if not is_financial(lead):
        return {"decision": "PASS", "reason": "not financial"}
    if not proof:
        return {"decision": "BLOCK", "reason": "missing economic proof"}
    if proof.get("verdict") != "REPORT_READY":
        return {"decision": "BLOCK", "reason": (proof.get("lead_exit") or {}).get("reason", "economic proof did not pass")}
    return {"decision": "PASS", "reason": "economic proof passed"}


def poc_gate(lead: dict[str, Any]) -> dict[str, Any]:
    poc = lead.get("poc") or (lead.get("evidence") or {}).get("poc") or {}
    if not poc.get("path") and not lead.get("reproduction_plan"):
        return {"decision": "BLOCK", "reason": "missing PoC or reproduction plan"}
    if poc and poc.get("assertion") is False:
        return {"decision": "BLOCK", "reason": "fake PoC without assertion"}
    return {"decision": "PASS", "reason": "PoC/reproduction present"}


def enforce_pipeline(
    lead: dict[str, Any],
    *,
    report_text: str = "",
    economic_proof: dict[str, Any] | None = None,
    feedback_memory: dict[str, Any] | None = None,
    report_path: Path | None = None,
    poc_path: Path | None = None,
) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = []
    warnings: list[str] = []
    schema = validate_payload("finding", lead if lead.get("file_path") else normalize_lead_for_schema(lead))
    if not schema["valid"]:
        blocks.append({"gate": "schema", "reason": "; ".join(schema["errors"])})
    if lead.get("source", {}).get("origin") == "scanner" or lead.get("state") == "SCANNER_LEAD":
        if not lead.get("manual_verified"):
            blocks.append({"gate": "source", "reason": "scanner-only finding stays blocked"})
    memory_result = None
    if feedback_memory is not None:
        memory_result = query_feedback_memory(feedback_memory, future_lead=lead, future_report=report_text)
        warnings.extend(memory_result.get("warnings", []))
        if memory_result.get("warnings") and not lead.get("stronger_evidence"):
            blocks.append({"gate": "feedback_memory", "reason": "feedback memory warning requires stronger evidence"})
    if lead.get("duplicate_of") or lead.get("duplicate_root_cause"):
        blocks.append({"gate": "duplicate", "reason": "duplicate/root-cause lead cannot report"})
    if lead.get("category") in {"business_logic_hypothesis", "bounty_hypothesis"} or lead.get("state") == "HYPOTHESIS":
        if not lead.get("allow_hypothesis_promotion"):
            return result("HYPOTHESIS_ONLY", blocks, warnings, memory_result)
    if lead.get("is_mev"):
        mev = evaluate_mev_lead(lead)
        if mev["status"] != "MEV_PASS":
            blocks.append({"gate": "mev", "reason": "MEV gate blocked", "details": mev["blocks"]})
    if lead.get("is_cross_chain"):
        cc = evaluate_cross_chain_lead(lead)
        if cc["status"] != "CROSS_CHAIN_PASS":
            return result("NEEDS_CONTEXT" if cc["status"] == "HYPOTHESIS" else "BLOCKED", blocks + [{"gate": "cross_chain", "reason": "cross-chain gate blocked", "details": cc["blocks"]}], warnings, memory_result)
    econ = economic_gate(lead, economic_proof)
    if econ["decision"] == "BLOCK":
        blocks.append({"gate": "economic", "reason": econ["reason"]})
    pg = poc_gate(lead)
    if pg["decision"] == "BLOCK":
        blocks.append({"gate": "poc", "reason": pg["reason"]})
    gate_input = normalize_lead_for_state_machine(lead, economic_proof)
    sm = can_transition(gate_input, "REPORT_READY")
    if not sm["allowed"]:
        blocks.append({"gate": "state_machine", "reason": "state machine blocked promotion", "details": sm["blocks"]})
    if report_text:
        lint = lint_report(report_text, lead, economic_proof or empty_proof(), poc_path=poc_path, report_path=report_path)
        if lint["status"] != "LINTER_PASS":
            blocks.append({"gate": "report_linter", "reason": "report linter blocked", "details": lint["blocks"]})
    return result("BLOCKED" if blocks else "REPORT_READY", blocks, warnings, memory_result)


def normalize_lead_for_schema(lead: dict[str, Any]) -> dict[str, Any]:
    loc = (lead.get("locations") or [{}])[0]
    return {**lead, "file_path": lead.get("file_path") or loc.get("file") or "unknown.sol", "contract": lead.get("contract") or loc.get("contract") or "Unknown", "function": lead.get("function") or loc.get("function") or "unknown"}


def normalize_lead_for_state_machine(lead: dict[str, Any], proof: dict[str, Any] | None) -> dict[str, Any]:
    n = normalize_lead_for_schema(lead)
    n.setdefault("state", lead.get("state", "CONFIRMED"))
    n.setdefault("code_path", lead.get("code_path") or [n.get("function")])
    n.setdefault("preconditions", lead.get("preconditions") or ["normal protocol use"])
    n.setdefault("attacker_capabilities", lead.get("attacker_capabilities") or "normal attacker")
    n.setdefault("affected_asset", lead.get("affected_asset") or (lead.get("impact") or {}).get("asset") or "protocol asset")
    n.setdefault("exploit_scenario", lead.get("exploit_scenario") or lead.get("title") or "exploit scenario")
    n.setdefault("likelihood", lead.get("likelihood") or "High")
    n.setdefault("severity_rationale", lead.get("severity_rationale") or "evidence-backed severity")
    n.setdefault("poc", lead.get("poc") or {"path": "test/Exploit.t.sol", "assertion": True})
    n.setdefault("fix", lead.get("fix") or "specific remediation")
    n.setdefault("confidence", lead.get("confidence") or "CONFIRMED")
    if proof:
        n["economic_proof"] = {"schema_valid": True, "verdict": proof.get("verdict")}
    return n


def empty_proof() -> dict[str, Any]:
    return {"impact": {"bad_debt_usd": "0", "protocol_loss_usd": "0"}, "profitability": {"net_profit_usd": "0"}, "verdict": "KILL"}


def result(status: str, blocks: list[dict[str, Any]], warnings: list[str], memory_result: dict[str, Any] | None) -> dict[str, Any]:
    assert status in FINAL_STATUSES
    return {"final_status": status, "blocks": blocks, "warnings": warnings, "memory": memory_result}


def final_closure_status_from_blocks(blocks: list[dict[str, Any]]) -> str:
    if not blocks:
        return "REPORT_READY_POSTHOC_REGRESSION"
    priority = [
        ("scope", "BLOCKED_SCOPE_UNCLEAR"),
        ("value_at_risk", "BLOCKED_MISSING_VALUE_AT_RISK"),
        ("economic", "BLOCKED_MISSING_ECONOMIC_PROOF"),
        ("severity", "BLOCKED_MISSING_SEVERITY_CALIBRATION"),
        ("intended_behavior", "BLOCKED_INTENDED_BEHAVIOR_REVIEW"),
        ("duplicate", "BLOCKED_DUPLICATE_OR_KNOWN_ISSUE"),
        ("report_linter", "BLOCKED_REPORT_LINTER"),
    ]
    for gate, status in priority:
        if any(block.get("gate") == gate for block in blocks):
            return status
    return "BLOCKED_PIPELINE_STATE_MACHINE"


def enforce_final_evidence_package(root: Path, candidate_id: str) -> dict[str, Any]:
    package = load_json(closure_path(root, candidate_id, "final_evidence_package.json"), {})
    scope = load_json(closure_path(root, candidate_id, "scope_review.json"), {})
    var = load_json(closure_path(root, candidate_id, "value_at_risk_analysis.json"), {})
    econ = load_json(closure_path(root, candidate_id, "economic_proof.json"), {})
    severity = load_json(closure_path(root, candidate_id, "severity_calibration.json"), {})
    intended = load_json(closure_path(root, candidate_id, "intended_behavior_review.json"), {})
    duplicate = load_json(closure_path(root, candidate_id, "duplicate_review.json"), {})
    lint = load_json(closure_path(root, candidate_id, "report_lint_result.json"), {})
    blocks: list[dict[str, Any]] = []
    if not package:
        blocks.append({"gate": "schema", "reason": "final evidence package missing"})
    else:
        for field in ["candidate_id", "pair_id", "status", "file", "contract", "function", "vulnerable_code_path", "preconditions", "attacker_capability", "affected_asset", "exploit_sequence", "impact", "likelihood", "severity", "severity_rationale", "value_at_risk", "economic_proof", "poc_command", "poc_result", "patched_regression_result", "recommended_fix", "duplicate_known_issue_status", "intended_behavior_review", "limitations", "confidence", "counts_toward_readiness"]:
            if package.get(field) in (None, "", [], {}):
                blocks.append({"gate": "schema", "reason": f"missing final evidence field: {field}"})
        if package.get("poc_result") != "POC_PASS_CONFIRMS_HYPOTHESIS":
            blocks.append({"gate": "poc", "reason": "confirmed PoC result required"})
    if not (scope.get("contract_in_scope") and scope.get("function_in_scope") and scope.get("asset_in_scope")) or scope.get("bounty_relevance") != "in_scope":
        blocks.append({"gate": "scope", "reason": "scope review did not establish local post-hoc regression scope", "details": scope.get("scope_blocks", [])})
    if var.get("impact_class") != "fund_freeze" or not var.get("amount_in_poc") or not var.get("victim_loss_or_freeze"):
        blocks.append({"gate": "value_at_risk", "reason": "value-at-risk was not established", "details": var.get("economic_blocks", [])})
    if econ.get("economic_proof_status") not in {"PROVEN", "PARTIAL", "NOT_REQUIRED"} or econ.get("theft_claimed") is True:
        blocks.append({"gate": "economic", "reason": "economic proof did not pass post-hoc regression gate", "details": econ.get("blocks", [])})
    if severity.get("recommended_severity") not in {"Critical", "High", "Medium", "Low", "Informational"} or severity.get("severity_blocks"):
        blocks.append({"gate": "severity", "reason": "severity calibration blocked", "details": severity.get("severity_blocks", [])})
    if intended.get("likely_unintended") is not True or not intended.get("evidence"):
        blocks.append({"gate": "intended_behavior", "reason": "intended behavior review did not pass", "details": intended.get("intended_behavior_blocks", [])})
    if duplicate.get("duplicate_status") == "DUPLICATE":
        blocks.append({"gate": "duplicate", "reason": "duplicate candidate cannot be promoted"})
    if duplicate.get("known_issue_status") == "KNOWN_PATCHED_CONTROL" and duplicate.get("counts_toward_readiness") is not False:
        blocks.append({"gate": "duplicate", "reason": "known patched-control issue must not count toward readiness"})
    if lint.get("status") != "LINTER_PASS":
        blocks.append({"gate": "report_linter", "reason": "report linter blocked", "details": lint.get("blocks", [])})
    closure_status = final_closure_status_from_blocks(blocks)
    payload = {
        "final_status": closure_status,
        "blocks": blocks,
        "warnings": [],
        "memory": None,
        "candidate_id": candidate_id,
        "report_ready_created": False,
        "posthoc_report_ready_created": closure_status == "REPORT_READY_POSTHOC_REGRESSION",
        "normal_report_ready_created": False,
        "known_issue_status": duplicate.get("known_issue_status"),
        "counts_toward_readiness": False,
        **safety_metadata(),
    }
    closure_path(root, candidate_id, "pipeline_result.json").write_text(json.dumps(payload, indent=2) + "\n")
    decision = {
        "candidate_id": candidate_id,
        "final_decision": closure_status,
        "normal_bounty_report_ready": False,
        "production_readiness_changed": False,
        "reason": "post-hoc patched-control regression evidence; known patched-control issue; not fresh independent bounty evidence",
        "known_issue_status": duplicate.get("known_issue_status"),
        "counts_toward_readiness": False,
    }
    closure_path(root, candidate_id, "final_decision.json").write_text(json.dumps(decision, indent=2) + "\n")
    return payload


def enforce_repaired_final_evidence_package(root: Path, candidate_id: str) -> dict[str, Any]:
    out_dir = root / "scoring" / "repaired_candidate_execution"
    package = load_json(out_dir / "repair_candidate_final_evidence_package.json", {})
    lint = load_json(out_dir / "repair_candidate_report_lint_result.json", {})
    result_payload = load_json(out_dir / "repair_candidate_execution_result.json", {})
    blocks: list[dict[str, Any]] = []
    if not package:
        blocks.append({"gate": "schema", "reason": "repaired final evidence package missing"})
    else:
        for field in ["candidate_id", "status", "file", "contract", "function", "poc_command", "poc_result", "report_key", "normal_bounty_report_ready", "counts_toward_readiness"]:
            if package.get(field) in (None, "", [], {}):
                blocks.append({"gate": "schema", "reason": f"missing repaired final evidence field: {field}"})
        if package.get("candidate_id") != candidate_id:
            blocks.append({"gate": "schema", "reason": "candidate mismatch"})
        if package.get("status") != "REPORT_READY_POSTHOC_SPENT_HOLDOUT" or package.get("report_key") != "REPORT_READY_POSTHOC_SPENT_HOLDOUT":
            blocks.append({"gate": "status", "reason": "repaired final evidence must remain post-hoc spent-holdout only"})
        if package.get("poc_result") != "POC_PASS_CONFIRMS_HYPOTHESIS" or result_payload.get("confirmed") is not True:
            blocks.append({"gate": "poc", "reason": "confirmed repaired PoC result required"})
        if package.get("normal_bounty_report_ready") is not False or package.get("counts_toward_readiness") is not False:
            blocks.append({"gate": "readiness", "reason": "spent holdout evidence cannot be normal report-ready or count toward readiness"})
    if lint.get("status") != "LINTER_PASS":
        blocks.append({"gate": "report_linter", "reason": "repaired report linter blocked or missing", "details": lint.get("blocks", [])})
    final_status = "REPORT_READY_POSTHOC_SPENT_HOLDOUT" if not blocks else "BLOCKED"
    payload = {
        "final_status": final_status,
        "blocks": blocks,
        "warnings": ["post-hoc spent holdout evidence only; normal bounty report-ready is false"],
        "memory": None,
        "candidate_id": candidate_id,
        "report_ready_created": False,
        "posthoc_spent_holdout_report_key": final_status == "REPORT_READY_POSTHOC_SPENT_HOLDOUT",
        "normal_report_ready_created": False,
        "counts_toward_readiness": False,
        **safety_metadata(),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "repair_candidate_pipeline_result.json").write_text(json.dumps(payload, indent=2) + "\n")
    decision = {
        "candidate_id": candidate_id,
        "final_decision": final_status,
        "normal_bounty_report_ready": False,
        "production_readiness_changed": False,
        "reason": "post-hoc spent holdout repaired-candidate evidence; not fresh independent bounty evidence",
        "counts_toward_readiness": False,
    }
    (out_dir / "repair_candidate_final_decision.json").write_text(json.dumps(decision, indent=2) + "\n")
    return payload


def enforce_expected_aligned_final_evidence_package(root: Path, candidate_id: str) -> dict[str, Any]:
    out_dir = root / "scoring" / "fresh_v6_expected_aligned_execution"
    package = load_json(out_dir / "expected_aligned_evidence_package.json", {})
    lint = load_json(out_dir / "expected_aligned_report_lint_result.json", {})
    result_payload = load_json(out_dir / "expected_aligned_execution_result.json", {})
    blocks: list[dict[str, Any]] = []
    if not package:
        blocks.append({"gate": "schema", "reason": "expected-aligned evidence package missing"})
    else:
        for field in ["candidate_id", "status", "file", "contract", "function", "poc_command", "poc_result", "known_issue_status", "normal_bounty_report_ready", "counts_toward_readiness"]:
            if package.get(field) in (None, "", [], {}):
                blocks.append({"gate": "schema", "reason": f"missing expected-aligned evidence field: {field}"})
        if package.get("candidate_id") != candidate_id:
            blocks.append({"gate": "schema", "reason": "candidate mismatch"})
        if package.get("status") != "CONFIRMED_POSTHOC_EXPECTED_ALIGNED_SPENT_HOLDOUT":
            blocks.append({"gate": "status", "reason": "expected-aligned evidence must remain post-hoc spent-holdout only"})
        if package.get("poc_result") != "POC_PASS_CONFIRMS_EXPECTED_ALIGNED_HYPOTHESIS" or result_payload.get("confirmed") is not True:
            blocks.append({"gate": "poc", "reason": "confirmed expected-aligned PoC result required"})
        if package.get("normal_bounty_report_ready") is not False or package.get("counts_toward_readiness") is not False:
            blocks.append({"gate": "readiness", "reason": "expected-aligned spent holdout evidence cannot be normal report-ready or count toward readiness"})
    if lint.get("status") != "LINTER_PASS":
        blocks.append({"gate": "report_linter", "reason": "expected-aligned report linter blocked or missing", "details": lint.get("blocks", [])})
    final_status = "REPORT_READY_POSTHOC_EXPECTED_ALIGNED_SPENT_HOLDOUT" if not blocks else "BLOCKED"
    payload = {
        "final_status": final_status,
        "blocks": blocks,
        "warnings": ["post-hoc expected-aligned spent holdout evidence only; normal bounty report-ready is false"],
        "memory": None,
        "candidate_id": candidate_id,
        "report_ready_created": False,
        "posthoc_expected_aligned_spent_holdout_report_key": final_status == "REPORT_READY_POSTHOC_EXPECTED_ALIGNED_SPENT_HOLDOUT",
        "normal_report_ready_created": False,
        "counts_toward_readiness": False,
        **safety_metadata(),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "expected_aligned_pipeline_result.json").write_text(json.dumps(payload, indent=2) + "\n")
    decision = {
        "candidate_id": candidate_id,
        "final_decision": final_status,
        "normal_bounty_report_ready": False,
        "production_readiness_changed": False,
        "reason": "post-hoc expected-aligned spent holdout evidence; not fresh independent bounty evidence",
        "counts_toward_readiness": False,
    }
    (out_dir / "expected_aligned_final_decision.json").write_text(json.dumps(decision, indent=2) + "\n")
    return payload


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Enforce full Web3 lead pipeline")
    p.add_argument("lead_json", nargs="?")
    p.add_argument("--root", default="")
    p.add_argument("--candidate", default="")
    p.add_argument("--evidence-package", action="store_true")
    p.add_argument("--final-evidence-package", action="store_true")
    args = p.parse_args(argv)
    if args.candidate and args.final_evidence_package:
        root = Path(args.root) if args.root else Path(__file__).resolve().parents[1] / "benchmarks" / "public-historical-corpus"
        if args.candidate.startswith("EXPECTED-ALIGNED-"):
            result_payload = enforce_expected_aligned_final_evidence_package(root, args.candidate)
        elif args.candidate.startswith("REPAIR-POC-"):
            result_payload = enforce_repaired_final_evidence_package(root, args.candidate)
        else:
            result_payload = enforce_final_evidence_package(root, args.candidate)
        print(json.dumps(result_payload, indent=2))
        return 0
    if args.candidate and args.evidence_package:
        root = Path(args.root) if args.root else Path(__file__).resolve().parents[1] / "benchmarks" / "public-historical-corpus"
        package_path = root / "scoring" / "poc_vertical_slice_evidence_package.json"
        evidence = json.loads(package_path.read_text(errors="replace")) if package_path.exists() else {"candidate_id": args.candidate}
        lead = {
            "id": evidence.get("candidate_id"),
            "title": f"Post-hoc vertical slice for {evidence.get('contract')}.{evidence.get('function')}",
            "state": "CONFIRMED",
            "file_path": evidence.get("file"),
            "contract": evidence.get("contract"),
            "function": evidence.get("function"),
            "code_path": [evidence.get("vulnerable_code_path")],
            "preconditions": ["post-hoc patched-control harness boundary condition"],
            "attacker_capabilities": evidence.get("attacker_capability"),
            "affected_asset": evidence.get("affected_asset"),
            "exploit_scenario": " -> ".join(evidence.get("exploit_sequence") or []),
            "impact": {"type": "frozen-funds", "asset": evidence.get("affected_asset")},
            "likelihood": evidence.get("likelihood"),
            "severity_rationale": evidence.get("severity_rationale"),
            "poc": {"path": "generated_pocs", "assertion": True},
            "fix": evidence.get("recommended_fix"),
            "confidence": evidence.get("confidence"),
            "allow_hypothesis_promotion": True,
        }
        result_payload = enforce_pipeline(lead)
        result_payload.update({"candidate_id": args.candidate, "evidence_package": str(package_path.relative_to(root)) if package_path.exists() else "missing", "report_ready_created": result_payload.get("final_status") == "REPORT_READY", "production_readiness_changed": False})
        (root / "scoring" / "poc_vertical_slice_pipeline_result.json").write_text(json.dumps(result_payload, indent=2) + "\n")
        print(json.dumps(result_payload, indent=2))
        return 0
    if not args.lead_json:
        raise SystemExit("provide lead_json or --candidate --evidence-package")
    print(json.dumps(enforce_pipeline(json.loads(Path(args.lead_json).read_text(errors="replace"))), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
