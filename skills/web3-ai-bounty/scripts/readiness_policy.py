#!/usr/bin/env python3
"""Readiness policy enforcement for Web3 audit evaluation results."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

PRODUCTION_READINESS_THRESHOLDS = {
    "report_ready_recall": 0.50,
    "report_ready_precision": 0.70,
    "patched_control_false_positive_rate": 0.10,
    "missed_critical_count": 0,
    "human_adjudication_acceptance_rate": 0.80,
}


FRESH_HOLDOUT_REQUIRED_FIELDS = [
    "source_coverage_gate_pass",
    "lead_budget_gate_pass",
    "frozen_outputs_before_scoring",
    "answer_key_report_isolation",
    "executed_or_equivalent_evidence",
    "value_at_risk_severity_calibrated",
    "report_linter_pass",
    "pipeline_pass",
    "fresh_confirmation_result_recorded",
    "human_adjudication_packet",
    "patched_control_false_positive_evidence_or_blocker",
]

POSTHOC_ONLY_REPORT_KEYS = {
    "REPORT_READY_POSTHOC_REGRESSION",
    "REPORT_READY_POSTHOC_SPENT_HOLDOUT",
    "REPORT_READY_POSTHOC_EXPECTED_ALIGNED_SPENT_HOLDOUT",
}


def report_status_counts_as_fresh_bounty(status: str) -> bool:
    if status in POSTHOC_ONLY_REPORT_KEYS:
        return False
    return status == "REPORT_READY"


def poc_artifact_counts_as_evidence(*, scaffold: bool = False, blocked: bool = False, posthoc: bool = False, confirmed: bool = False) -> bool:
    if scaffold or blocked or posthoc:
        return False
    return confirmed


def apply_policy(metrics: dict[str, Any]) -> dict[str, Any]:
    holdout_recall = float(metrics.get("public_holdout_finding_recall", metrics.get("independent_holdout_finding_recall", 0.0)) or 0.0)
    holdout_repos = int(metrics.get("public_holdout_case_count", metrics.get("independent_holdout_case_count", 0)) or 0)
    patched_controls = int(metrics.get("public_patched_case_count", metrics.get("patched_control_count", 0)) or 0)
    zero_guard_failed = bool(metrics.get("zero_finding_guard_failed") or metrics.get("invalid_low_coverage") or metrics.get("zero_guard_status") in {"INVALID_LOW_COVERAGE", "FAIL"})
    lead_budget_failed = bool(metrics.get("lead_budget_guard_failed") or metrics.get("lead_budget_status") == "FAIL")
    no_overfit_failed = bool(metrics.get("no_overfit_guard_failed") or metrics.get("no_overfit_status") == "FAIL")
    source_coverage_low_confidence = bool(metrics.get("source_coverage_low_confidence") or metrics.get("coverage_status") == "LOW_CONFIDENCE")
    synthetic_success = bool(metrics.get("synthetic_success"))
    posthoc_regression_report_ready_count = int(metrics.get("posthoc_regression_report_ready_count", 0) or 0)
    posthoc_spent_holdout_report_ready_count = int(metrics.get("posthoc_spent_holdout_report_ready_count", metrics.get("report_ready_posthoc_spent_holdout_count", 0)) or 0)
    posthoc_expected_aligned_spent_holdout_report_ready_count = int(metrics.get("posthoc_expected_aligned_spent_holdout_report_ready_count", metrics.get("report_ready_posthoc_expected_aligned_spent_holdout_count", 0)) or 0)
    posthoc_report_ready_count = posthoc_regression_report_ready_count + posthoc_spent_holdout_report_ready_count + posthoc_expected_aligned_spent_holdout_report_ready_count
    known_patched_control_count = int(metrics.get("known_patched_control_count", metrics.get("patched_control_report_ready_count", 0)) or 0)
    hypothesis_count = int(metrics.get("hypothesis_generated_count", metrics.get("hypotheses_count", 0)) or 0)
    executed_posthoc_pocs = int(metrics.get("executed_posthoc_poc_count", 0) or 0)
    executed_posthoc_expected_aligned_pocs = int(metrics.get("executed_posthoc_expected_aligned_poc_count", 0) or 0)
    repaired_spent_holdout_pocs = int(metrics.get("repaired_spent_holdout_poc_count", metrics.get("spent_holdout_repaired_poc_count", 0)) or 0)
    strict_expected_aligned_spent_match_count = int(metrics.get("strict_expected_aligned_spent_match_count", metrics.get("expected_aligned_spent_strict_match_count", 0)) or 0)
    poc_scaffold_count = int(metrics.get("poc_scaffold_count", 0) or 0)
    blocked_poc_count = int(metrics.get("blocked_poc_count", metrics.get("poc_blocked_count", 0)) or 0)
    fresh_holdout_required = True
    fresh_holdout_complete = has_complete_fresh_holdout_evidence(metrics)
    production_threshold_met = meets_production_threshold(metrics) if fresh_holdout_complete else False

    public_generalization = "not_ready" if holdout_recall < 0.5 else "candidate_requires_patched_controls_and_human_review"
    real_autonomy = "not_ready" if holdout_recall == 0.0 and holdout_repos >= 3 else "not_ready_without_more_evidence"
    production = "not_production_ready"
    if production_threshold_met and not (zero_guard_failed or lead_budget_failed or no_overfit_failed or source_coverage_low_confidence):
        production = "production_ready_candidate_pending_final_human_approval"
    elif holdout_recall >= 0.5 and patched_controls > 0 and not zero_guard_failed:
        production = "beta_not_production_ready_pending_human_adjudication"
    if patched_controls == 0:
        production_cap = "below_production_no_patched_controls"
    else:
        production_cap = "not_capped_by_patched_controls"
    if zero_guard_failed or lead_budget_failed or no_overfit_failed or source_coverage_low_confidence:
        production = "not_production_ready"
    return {
        "status": "PASS",
        "public_contest_generalization": public_generalization,
        "real_protocol_autonomy": real_autonomy,
        "production_readiness": production,
        "controlled_solidity_assistance": "beta_for_known_benchmarked_patterns",
        "non_evm_readiness": "limited",
        "production_cap": production_cap,
        "zero_finding_guard_blocks_readiness": zero_guard_failed,
        "lead_budget_guard_blocks_readiness": lead_budget_failed,
        "no_overfit_guard_blocks_readiness": no_overfit_failed,
        "source_coverage_low_confidence_blocks_readiness": source_coverage_low_confidence,
        "synthetic_success_overrides_public_failure": False,
        "synthetic_success_considered": synthetic_success,
        "posthoc_report_ready_count": posthoc_report_ready_count,
        "posthoc_report_ready_counts_as_fresh_bounty": False,
        "posthoc_regression_report_ready_counts_as_fresh_bounty": False,
        "posthoc_spent_holdout_report_ready_count": posthoc_spent_holdout_report_ready_count,
        "posthoc_spent_holdout_report_ready_counts_as_fresh_bounty": False,
        "posthoc_expected_aligned_spent_holdout_report_ready_count": posthoc_expected_aligned_spent_holdout_report_ready_count,
        "posthoc_expected_aligned_spent_holdout_report_ready_counts_as_fresh_bounty": False,
        "repaired_spent_holdout_poc_count": repaired_spent_holdout_pocs,
        "repaired_spent_holdout_poc_counts_as_fresh_bounty": False,
        "spent_fresh_holdout_repaired_pocs_count_toward_production": False,
        "strict_expected_aligned_spent_match_count": strict_expected_aligned_spent_match_count,
        "strict_expected_aligned_spent_match_counts_as_fresh_bounty": False,
        "strict_expected_aligned_spent_match_counts_toward_production_readiness": False,
        "known_patched_control_count": known_patched_control_count,
        "known_patched_controls_count_as_fresh_bounty": False,
        "known_patched_controls_count_toward_production_readiness": False,
        "poc_scaffold_count": poc_scaffold_count,
        "poc_scaffolds_count_as_evidence": False,
        "blocked_poc_count": blocked_poc_count,
        "blocked_pocs_count_as_evidence": False,
        "fresh_independent_holdout_required_for_production": fresh_holdout_required,
        "fresh_independent_confirmed_findings_required_for_production": True,
        "fresh_independent_detection_required_for_normal_report_ready": True,
        "fresh_outputs_must_be_generated_before_answer_key_or_report_access": True,
        "fresh_holdout_evidence_complete": fresh_holdout_complete,
        "production_threshold_met": production_threshold_met,
        "hypotheses_improve_copilot_not_production_readiness": hypothesis_count > 0,
        "executed_posthoc_poc_count": executed_posthoc_pocs,
        "executed_posthoc_expected_aligned_poc_count": executed_posthoc_expected_aligned_pocs,
        "executed_posthoc_expected_aligned_poc_counts_toward_production_readiness": False,
        "executed_posthoc_pocs_improve_workflow_confidence_only": executed_posthoc_pocs > 0 or executed_posthoc_expected_aligned_pocs > 0 or repaired_spent_holdout_pocs > 0 or posthoc_report_ready_count > 0,
        "report_ready_posthoc_regression_allowed_status": "workflow_regression_only",
        "report_ready_posthoc_expected_aligned_allowed_status": "posthoc_expected_aligned_spent_holdout_only",
        "posthoc_success_can_override_fresh_failure": False,
        "normal_report_ready_fresh_requirements": {
            "source_coverage_pass": True,
            "lead_budget_pass": True,
            "frozen_outputs_before_scoring": True,
            "no_report_or_answer_key_leakage": True,
            "executed_or_equivalent_evidence": True,
            "value_at_risk_and_severity_calibration": True,
            "report_linter_pass": True,
            "pipeline_pass": True,
            "human_adjudication_where_semantic_matching_needed": True,
        },
        "basis": {
            "holdout_finding_recall": holdout_recall,
            "holdout_repo_count": holdout_repos,
            "patched_control_count": patched_controls,
            "zero_guard_failed": zero_guard_failed,
            "lead_budget_failed": lead_budget_failed,
            "no_overfit_failed": no_overfit_failed,
            "source_coverage_low_confidence": source_coverage_low_confidence,
            "fresh_holdout_required_fields": {field: bool(metrics.get(field)) for field in FRESH_HOLDOUT_REQUIRED_FIELDS},
        },
    }


def has_complete_fresh_holdout_evidence(metrics: dict[str, Any]) -> bool:
    return all(bool(metrics.get(field)) for field in FRESH_HOLDOUT_REQUIRED_FIELDS)


def meets_production_threshold(metrics: dict[str, Any]) -> bool:
    def f(key: str, default: float) -> float:
        value = metrics.get(key, default)
        return default if value is None or value == "" else float(value)

    def i(key: str, default: int) -> int:
        value = metrics.get(key, default)
        return default if value is None or value == "" else int(value)

    return (
        f("report_ready_recall", 0.0) >= PRODUCTION_READINESS_THRESHOLDS["report_ready_recall"]
        and f("report_ready_precision", 0.0) >= PRODUCTION_READINESS_THRESHOLDS["report_ready_precision"]
        and f("patched_control_false_positive_rate", 1.0) <= PRODUCTION_READINESS_THRESHOLDS["patched_control_false_positive_rate"]
        and i("missed_critical_count", 999) == PRODUCTION_READINESS_THRESHOLDS["missed_critical_count"]
        and f("human_adjudication_acceptance_rate", 0.0) >= PRODUCTION_READINESS_THRESHOLDS["human_adjudication_acceptance_rate"]
        and i("fresh_independent_confirmed_finding_count", i("report_ready_generated_count", 0)) > 0
    )


def check_posthoc_regression_policy() -> dict[str, Any]:
    posthoc = apply_policy({
        "posthoc_regression_report_ready_count": 1,
        "posthoc_spent_holdout_report_ready_count": 1,
        "posthoc_expected_aligned_spent_holdout_report_ready_count": 1,
        "known_patched_control_count": 1,
        "executed_posthoc_poc_count": 3,
        "executed_posthoc_expected_aligned_poc_count": 1,
        "repaired_spent_holdout_poc_count": 1,
        "strict_expected_aligned_spent_match_count": 1,
        "public_holdout_finding_recall": 0.0,
        "public_holdout_case_count": 3,
        "public_patched_case_count": 3,
    })
    fresh = apply_policy({
        "source_coverage_gate_pass": True,
        "lead_budget_gate_pass": True,
        "frozen_outputs_before_scoring": True,
        "answer_key_report_isolation": True,
        "executed_or_equivalent_evidence": True,
        "value_at_risk_severity_calibrated": True,
        "report_linter_pass": True,
        "pipeline_pass": True,
        "fresh_confirmation_result_recorded": True,
        "human_adjudication_packet": True,
        "patched_control_false_positive_evidence_or_blocker": True,
        "public_holdout_finding_recall": 0.75,
        "public_holdout_case_count": 3,
        "public_patched_case_count": 3,
        "report_ready_recall": 0.50,
        "report_ready_precision": 0.70,
        "patched_control_false_positive_rate": 0.10,
        "missed_critical_count": 0,
        "human_adjudication_acceptance_rate": 0.80,
        "fresh_independent_confirmed_finding_count": 1,
    })
    ok = (
        posthoc["production_readiness"] == "not_production_ready"
        and posthoc["posthoc_report_ready_counts_as_fresh_bounty"] is False
        and posthoc["posthoc_spent_holdout_report_ready_counts_as_fresh_bounty"] is False
        and posthoc["posthoc_expected_aligned_spent_holdout_report_ready_counts_as_fresh_bounty"] is False
        and posthoc["repaired_spent_holdout_poc_counts_as_fresh_bounty"] is False
        and posthoc["strict_expected_aligned_spent_match_counts_as_fresh_bounty"] is False
        and posthoc["executed_posthoc_expected_aligned_poc_counts_toward_production_readiness"] is False
        and posthoc["known_patched_controls_count_as_fresh_bounty"] is False
        and posthoc["fresh_independent_holdout_required_for_production"] is True
        and posthoc["fresh_independent_detection_required_for_normal_report_ready"] is True
        and posthoc["posthoc_success_can_override_fresh_failure"] is False
        and fresh["production_threshold_met"] is True
    )
    return {"status": "PASS" if ok else "FAIL", "posthoc_regression": posthoc, "fresh_threshold_example": fresh}


def load_metrics(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(errors="replace"))
    if "metrics" in payload and "public_holdout_finding_recall" not in payload:
        return payload["metrics"]
    return payload


def self_test() -> dict[str, Any]:
    zero = apply_policy({"public_holdout_finding_recall": 0.0, "public_holdout_case_count": 3, "public_patched_case_count": 0, "synthetic_success": True})
    guarded = apply_policy({"public_holdout_finding_recall": 0.8, "public_holdout_case_count": 3, "public_patched_case_count": 3, "zero_finding_guard_failed": True})
    budget = apply_policy({"public_holdout_finding_recall": 0.8, "public_holdout_case_count": 3, "public_patched_case_count": 3, "lead_budget_status": "FAIL"})
    posthoc = check_posthoc_regression_policy()
    ok = zero["real_protocol_autonomy"] == "not_ready" and zero["production_readiness"] == "not_production_ready" and zero["synthetic_success_overrides_public_failure"] is False and guarded["zero_finding_guard_blocks_readiness"] is True and budget["lead_budget_guard_blocks_readiness"] is True and posthoc["status"] == "PASS"
    return {"status": "PASS" if ok else "FAIL", "zero_recall": zero, "guarded": guarded, "budget": budget, "posthoc_policy": posthoc}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Apply readiness policy to public contest metrics")
    p.add_argument("--metrics-json", default="")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--check-posthoc-regression", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        result = self_test()
    elif args.check_posthoc_regression:
        result = check_posthoc_regression_policy()
    elif args.metrics_json:
        result = apply_policy(load_metrics(Path(args.metrics_json)))
    else:
        raise SystemExit("provide --metrics-json or --self-test")
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
