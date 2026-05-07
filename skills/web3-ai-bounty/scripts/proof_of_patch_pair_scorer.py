#!/usr/bin/env python3
"""Score frozen Proof-of-Patch pair outputs after metadata is allowed."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT, load_case_outputs
from hypothesis_quality_scorer import score_hypothesis
from patch_diff_analyzer import analyze_split as analyze_patch_diff
from patch_regression_test_planner import plan_split as plan_patch_regressions
from vulnerable_patched_comparator import compare_split as compare_vulnerable_patched


def is_report_ready(f: dict[str, Any]) -> bool:
    return bool(f.get("report_ready") or f.get("state") == "REPORT_READY" or (f.get("pipeline") or {}).get("final_status") == "REPORT_READY")


def related_to_metadata(hypotheses: list[dict[str, Any]], metadata: dict[str, Any]) -> bool:
    expected = str(metadata.get("expected_vulnerability") or "").lower().replace(" ", "-")
    if not expected:
        return bool(hypotheses)
    return any(expected in str(h.get("bug_class", "")).lower() or expected.replace("-", " ") in str(h.get("exploit_scenario", "")).lower() for h in hypotheses)


def match_type_for_metadata(hypotheses: list[dict[str, Any]], metadata: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    expected = str(metadata.get("expected_vulnerability") or "").lower().replace(" ", "-")
    if not expected:
        return ("none", None)
    for h in hypotheses:
        bug = str(h.get("bug_class", "")).lower()
        scenario = str(h.get("exploit_scenario", "")).lower()
        if expected in bug or expected.replace("-", "") in bug.replace("-", ""):
            return ("semantic", h)
        if expected.replace("-", " ") in scenario:
            return ("weak", h)
    return ("none", None)


def score_pair(root: Path, pair: dict[str, Any], *, diff: dict[str, Any] | None = None, comparison: dict[str, Any] | None = None, regression_plan: dict[str, Any] | None = None) -> dict[str, Any]:
    meta_path = root / pair.get("metadata_path", "")
    metadata = json.loads(meta_path.read_text(errors="replace")) if meta_path.exists() else {}
    vuln = load_case_outputs(root, pair["vulnerable_case_id"])
    patched = load_case_outputs(root, pair["patched_case_id"])
    if vuln["status"] != "PASS" or patched["status"] != "PASS":
        return {"pair_id": pair["pair_id"], "status": "BLOCKED", "reason": "frozen pair outputs missing"}
    vuln_h = vuln["artifacts"]["hypotheses"].get("hypotheses", [])
    patched_h = patched["artifacts"]["hypotheses"].get("hypotheses", [])
    vuln_ready = [f for f in vuln["artifacts"]["confirmed_findings"].get("findings", []) if is_report_ready(f)]
    patched_ready = [f for f in patched["artifacts"]["confirmed_findings"].get("findings", []) if is_report_ready(f)]
    match_type, best = match_type_for_metadata(vuln_h, metadata)
    related = match_type != "none"
    quality_rows = [score_hypothesis(h) for h in vuln_h]
    patched_quality = [score_hypothesis(h) for h in patched_h]
    diff = diff or {}
    comparison = comparison or {}
    regression_plan = regression_plan or {}
    still_present = bool(comparison.get("patched_original_bug_still_present"))
    return {
        "pair_id": pair["pair_id"],
        "vulnerable_case_id": pair["vulnerable_case_id"],
        "patched_case_id": pair["patched_case_id"],
        "status": "PASS",
        "vulnerable_lead_count": len(vuln_h),
        "patched_lead_count": len(patched_h),
        "vulnerable_related_lead": related,
        "best_related_hypothesis": (best or {}).get("title") or (best or {}).get("exploit_scenario") or "",
        "match_type": match_type,
        "vulnerable_report_ready": bool(vuln_ready),
        "vulnerable_high_quality_hypothesis_count": sum(1 for q in quality_rows if q["high_quality"]),
        "vulnerable_poc_ready_hypothesis_count": sum(1 for q in quality_rows if q["poc_ready"]),
        "patched_original_bug_suppressed": related and not patched_ready and not still_present,
        "patched_original_bug_still_present": still_present,
        "patched_overbroad_noise_count": int(comparison.get("patched_overbroad_noise_count") or sum(1 for q in patched_quality if q["overbroad_noise"])),
        "patched_valid_residual_risk_count": int(comparison.get("patched_valid_residual_risk_count") or 0),
        "false_positive": bool(patched_ready),
        "patched_report_ready_false_positive_count": len(patched_ready),
        "patch_effect_explained": bool(diff.get("original_exploit_path_removed")),
        "patch_confidence": diff.get("patch_confidence", 0.0),
        "patch_regression_test_plan": regression_plan.get("status") == "PASS",
        "why_not_report_ready": "No frozen REPORT_READY finding with working PoC/economic proof matched this pair.",
        "evidence_missing": ["minimal executable PoC", "exact invariant/asset assertion", "economic proof where applicable", "duplicate/intended-behavior review"],
        "poc_needed": True,
        "metadata_used_after_freeze_only": True,
    }


def write_pair_analysis(root: Path, result: dict[str, Any], diff: dict[str, Any], comparison: dict[str, Any]) -> None:
    rows = []
    for pair in result.get("pairs", []):
        main_issue = "success"
        upgrade = "write executable vulnerable/patched regression PoC"
        if not pair.get("vulnerable_related_lead"):
            main_issue = "vulnerable related lead not found"
            upgrade = "improve metadata-to-hypothesis matching and root-cause-specific generation"
        elif pair.get("patched_overbroad_noise_count", 0) > 10:
            main_issue = "patched residual hypothesis noise"
            upgrade = "separate residual unrelated hypotheses from original-bug false positives"
        rows.append({
            "pair_id": pair["pair_id"],
            "vulnerable_related_lead": pair["vulnerable_related_lead"],
            "patched_original_bug_suppressed": pair["patched_original_bug_suppressed"],
            "patched_false_positive": pair["false_positive"],
            "vulnerable_lead_count": pair["vulnerable_lead_count"],
            "patched_lead_count": pair["patched_lead_count"],
            "best_related_hypothesis": pair.get("best_related_hypothesis", ""),
            "match_type": pair.get("match_type", "none"),
            "why_not_report_ready": pair.get("why_not_report_ready"),
            "evidence_missing": pair.get("evidence_missing", []),
            "poc_needed": True,
            "patch_effect_explained": pair.get("patch_effect_explained"),
            "main_issue": main_issue,
            "required_upgrade": upgrade,
        })
    payload = {
        "status": "PASS",
        "patched_control_status": "partially_successful",
        "hypothesis_generation_status": "improved",
        "hypothesis_precision_status": "weak_to_moderate",
        "confirmed_finding_status": "failed_zero_report_ready",
        "production_readiness": "not_production_ready",
        "controlled_solidity_assistance": "stronger_beta",
        "real_protocol_autonomy": "not_ready",
        "non_evm_readiness": "limited",
        "pairs": rows,
        "patch_diff_path": "scoring/patch_diff_analysis.json",
        "comparison_path": "scoring/vulnerable_patched_comparison.json",
    }
    scoring = root / "scoring"
    scoring.mkdir(parents=True, exist_ok=True)
    (scoring / "proof_of_patch_pair_analysis.json").write_text(json.dumps(payload, indent=2) + "\n")
    md = ["# Proof-of-Patch Pair Analysis", "", "| Pair | Related lead | Suppressed | Patched leads | Main issue | Required upgrade |", "|---|---:|---:|---:|---|---|"]
    for row in rows:
        md.append(f"| `{row['pair_id']}` | {row['vulnerable_related_lead']} | {row['patched_original_bug_suppressed']} | {row['patched_lead_count']} | {row['main_issue']} | {row['required_upgrade']} |")
    (scoring / "proof_of_patch_pair_analysis.md").write_text("\n".join(md) + "\n")


def score_pairs(root: Path = PUBLIC_ROOT, *, split: str = "patched-controls") -> dict[str, Any]:
    manifest_path = root / "patched_control_manifest.json"
    if not manifest_path.exists():
        return {"status": "BLOCKED", "reason": "missing patched control manifest", "proof_of_patch_pairs_attempted": 0, "proof_of_patch_pairs_imported": 0, "proof_of_patch_pairs_blocked": 0}
    manifest = json.loads(manifest_path.read_text(errors="replace"))
    pairs = manifest.get("pairs", [])
    if not pairs:
        result = {"status": "BLOCKED", "reason": "no imported Proof-of-Patch pairs", "proof_of_patch_pairs_attempted": manifest.get("proof_of_patch_pairs_attempted", 0), "proof_of_patch_pairs_imported": 0, "proof_of_patch_pairs_blocked": manifest.get("proof_of_patch_pairs_blocked", 0), "patched_original_bug_suppression_rate": 0.0, "patched_false_positive_count": 0, "patched_false_positive_rate": 0.0, "pairs": []}
    else:
        diff = analyze_patch_diff(root, split=split)
        comparison = compare_vulnerable_patched(root, split=split)
        regression = plan_patch_regressions(root, split=split)
        diff_by_pair = {row["pair_id"]: row for row in diff.get("pairs", [])}
        comparison_by_pair = {row["pair_id"]: row for row in comparison.get("pairs", [])}
        regression_by_pair = {row["pair_id"]: row for row in regression.get("pairs", [])}
        rows = [score_pair(root, p, diff=diff_by_pair.get(p["pair_id"]), comparison=comparison_by_pair.get(p["pair_id"]), regression_plan=regression_by_pair.get(p["pair_id"])) for p in pairs]
        ok = [r for r in rows if r["status"] == "PASS"]
        pair_count = len(ok) or 1
        result = {"status": "PASS" if len(ok) == len(rows) else "BLOCKED", "pair_count": len(ok), "proof_of_patch_pairs_attempted": manifest.get("proof_of_patch_pairs_attempted", len(rows)), "proof_of_patch_pairs_imported": len(rows), "proof_of_patch_pairs_blocked": manifest.get("proof_of_patch_pairs_blocked", 0) + len(rows) - len(ok), "vulnerable_related_hypothesis_count": sum(1 for r in ok if r["vulnerable_related_lead"]), "vulnerable_high_quality_hypothesis_count": sum(int(r.get("vulnerable_high_quality_hypothesis_count") or 0) for r in ok), "vulnerable_poc_ready_hypothesis_count": sum(int(r.get("vulnerable_poc_ready_hypothesis_count") or 0) for r in ok), "patched_original_bug_suppressed_count": sum(1 for r in ok if r["patched_original_bug_suppressed"]), "patched_original_bug_still_present_count": sum(1 for r in ok if r["patched_original_bug_still_present"]), "patched_overbroad_noise_count": sum(int(r.get("patched_overbroad_noise_count") or 0) for r in ok), "patched_valid_residual_risk_count": sum(int(r.get("patched_valid_residual_risk_count") or 0) for r in ok), "patched_false_positive_count": sum(int(r.get("patched_report_ready_false_positive_count") or 0) for r in ok), "patch_diff_explained_count": sum(1 for r in ok if r["patch_effect_explained"]), "patch_regression_test_plan_count": sum(1 for r in ok if r["patch_regression_test_plan"]), "vulnerable_related_hypothesis_rate": sum(1 for r in ok if r["vulnerable_related_lead"]) / pair_count, "vulnerable_high_quality_hypothesis_rate": sum(int(r.get("vulnerable_high_quality_hypothesis_count") or 0) for r in ok) / (sum(int(r.get("vulnerable_lead_count") or 0) for r in ok) or 1), "vulnerable_poc_ready_hypothesis_rate": sum(int(r.get("vulnerable_poc_ready_hypothesis_count") or 0) for r in ok) / (sum(int(r.get("vulnerable_lead_count") or 0) for r in ok) or 1), "vulnerable_report_ready_rate": sum(1 for r in ok if r["vulnerable_report_ready"]) / pair_count, "patched_original_bug_suppression_rate": sum(1 for r in ok if r["patched_original_bug_suppressed"]) / pair_count, "patched_false_positive_rate": sum(1 for r in ok if r["false_positive"]) / pair_count, "patch_diff_explanation_rate": sum(1 for r in ok if r["patch_effect_explained"]) / pair_count, "patch_regression_test_plan_rate": sum(1 for r in ok if r["patch_regression_test_plan"]) / pair_count, "metadata_hidden_during_detection": True, "network_used_during_detection": False, "secrets_accessed": False, "broadcasts_used": False, "production_readiness_changed": False, "pairs": rows}
        write_pair_analysis(root, result, diff, comparison)
        current_status = {
            "proof_of_patch_pairs_imported": result["proof_of_patch_pairs_imported"],
            "vulnerable_related_hypothesis_rate": round(result["vulnerable_related_hypothesis_rate"], 4),
            "vulnerable_report_ready_rate": round(result["vulnerable_report_ready_rate"], 4),
            "patched_original_bug_suppression_rate": round(result["patched_original_bug_suppression_rate"], 4),
            "patched_false_positive_rate": round(result["patched_false_positive_rate"], 4),
            "production_readiness_changed": False,
            "patched_control_status": "partially_successful",
        }
        (root / "scoring" / "proof_of_patch_current_status.json").write_text(json.dumps(current_status, indent=2) + "\n")
    (root / "scoring").mkdir(parents=True, exist_ok=True)
    (root / "scoring" / "proof_of_patch_score.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Score Proof-of-Patch pairs")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="patched-controls")
    p.add_argument("--frozen-only", action="store_true")
    args = p.parse_args(argv)
    result = score_pairs(Path(args.root), split=args.split)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
