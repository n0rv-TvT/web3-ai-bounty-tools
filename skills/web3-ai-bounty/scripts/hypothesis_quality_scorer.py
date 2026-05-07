#!/usr/bin/env python3
"""Score bounty hypotheses as triage artifacts, not findings."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT, case_ids_for_split, load_case_outputs

PRECISION_REGENERATION_DIR = "precision_regeneration"


def has_specific(value: Any) -> bool:
    return bool(value and str(value).strip() and str(value).strip().lower() not in {"requires validation", "unknown"})


def exploit_sequence_present(h: dict[str, Any]) -> bool:
    text = str(h.get("exploit_scenario") or "").lower()
    return any(w in text for w in ["attacker", "because", "causing", "if", "can reach", "enters", "supplies", "manipulates", "steps", "then", "withdraws", "replays"])


def poc_idea_present(h: dict[str, Any]) -> bool:
    poc = h.get("poc") or {}
    return bool(
        poc.get("idea")
        or poc.get("plan")
        or poc.get("assertion")
        or h.get("poc_idea")
        or h.get("minimal_poc_plan")
    )


def assertion_present(h: dict[str, Any]) -> bool:
    poc = h.get("poc") or {}
    minimal = h.get("minimal_poc_idea") or h.get("minimal_poc_plan") or {}
    return bool(poc.get("assertion") or minimal.get("assertions") or h.get("poc_assertion"))


def kill_condition_present(h: dict[str, Any]) -> bool:
    return bool(h.get("kill_condition") or (h.get("poc") or {}).get("kill_condition") or h.get("kill_if"))


def evidence_missing_present(h: dict[str, Any]) -> bool:
    return bool(h.get("evidence_missing") or h.get("promotion_blockers") or h.get("missing_evidence"))


def component_only(h: dict[str, Any], checks: dict[str, bool]) -> bool:
    return bool(has_specific(h.get("contract")) and (not checks["specific_file_contract_function"] or not checks["exploit_sequence"] or not checks["asset_at_risk"]))


def score_hypothesis(h: dict[str, Any]) -> dict[str, Any]:
    checks: dict[str, bool] = {
        "specific_file_contract_function": has_specific(h.get("file_path")) and has_specific(h.get("contract")) and has_specific(h.get("function")),
        "specific_lifecycle_or_component": "lifecycle_phase" in json.dumps(h.get("external_evidence", [])) or has_specific(h.get("contract")),
        "root_cause_clarity": has_specific(h.get("bug_class")) and "business-logic" not in str(h.get("bug_class", "")),
        "attacker_capability": has_specific(h.get("attacker_capabilities")),
        "asset_at_risk": has_specific(h.get("affected_asset")) and "requires validation" not in str(h.get("affected_asset", "")).lower(),
        "exploit_sequence": exploit_sequence_present(h),
        "impact_condition": isinstance(h.get("impact"), dict) and has_specific((h.get("impact") or {}).get("type")),
        "evidence_present": bool(h.get("external_evidence")),
        "evidence_missing_labeled": evidence_missing_present(h),
        "poc_idea": poc_idea_present(h),
        "kill_condition": kill_condition_present(h),
        "uncertainty_labeled": "hypothesis" in str(h.get("severity_rationale", "") + h.get("state", "")).lower(),
        "not_overstated": not bool(h.get("report_ready")) and h.get("state") == "HYPOTHESIS",
    }
    score = sum(1 for v in checks.values() if v) * 10.0 / len(checks)
    caps = []
    is_component_only = component_only(h, checks)
    if is_component_only:
        caps.append(4.0)
    if not checks["exploit_sequence"]:
        caps.append(5.0)
    if not checks["specific_file_contract_function"]:
        caps.append(6.0)
    if not checks["poc_idea"]:
        caps.append(7.0)
    if not checks["kill_condition"]:
        caps.append(7.0)
    if not checks["asset_at_risk"] or not checks["root_cause_clarity"]:
        caps.append(6.5)
    if not checks["not_overstated"]:
        caps.append(0.0)
    if caps:
        score = min(score, min(caps))
    missing = [k for k, v in checks.items() if not v]
    rounded = round(score, 2)
    poc_ready = rounded >= 7.0 and checks["poc_idea"] and checks["kill_condition"] and checks["specific_file_contract_function"]
    kill_ready = checks["kill_condition"] and checks["evidence_missing_labeled"]
    overbroad_noise = is_component_only or rounded < 5.0 or not checks["specific_file_contract_function"]
    return {
        "hypothesis_id": h.get("id") or h.get("lead_id"),
        "quality_score": rounded,
        "checks": checks,
        "missing_quality_factors": missing,
        "component_only_weak_lead": is_component_only,
        "component_only": is_component_only,
        "poc_ready": poc_ready,
        "kill_ready": kill_ready,
        "overbroad_noise": overbroad_noise,
        "quality_gate_failed": not checks["not_overstated"],
        "high_quality": rounded >= 8.0 and poc_ready and not overbroad_noise,
        "counts_as_finding": False,
        "report_ready": False,
    }


def normalize_regenerated_hypothesis(h: dict[str, Any]) -> dict[str, Any]:
    """Map regenerated precision schema back to the frozen-hypothesis scorer schema."""
    normalized = dict(h)
    if not normalized.get("id"):
        normalized["id"] = normalized.get("hypothesis_id") or normalized.get("lead_id")
    if not normalized.get("lead_id"):
        normalized["lead_id"] = normalized.get("hypothesis_id") or normalized.get("id")
    if not normalized.get("attacker_capabilities"):
        normalized["attacker_capabilities"] = normalized.get("attacker_capability")
    if not normalized.get("external_evidence"):
        normalized["external_evidence"] = normalized.get("evidence_found") or []
    if not normalized.get("promotion_blockers") and normalized.get("evidence_missing"):
        normalized["promotion_blockers"] = normalized.get("evidence_missing")
    if not normalized.get("poc") and normalized.get("minimal_poc_idea"):
        minimal = normalized.get("minimal_poc_idea") or {}
        normalized["poc"] = {
            "idea": minimal.get("poc_type") or minimal.get("task_type") or "Foundry local confirmation PoC",
            "assertion": bool(minimal.get("assertions")),
            "kill_condition": minimal.get("kill_condition") or normalized.get("kill_condition"),
        }
    if not normalized.get("poc_idea") and normalized.get("minimal_poc_idea"):
        normalized["poc_idea"] = (normalized.get("minimal_poc_idea") or {}).get("poc_type") or "Foundry local confirmation PoC"
    if not normalized.get("kill_condition") and isinstance(normalized.get("poc"), dict):
        normalized["kill_condition"] = normalized["poc"].get("kill_condition")
    if not normalized.get("state"):
        normalized["state"] = "HYPOTHESIS"
    normalized["report_ready"] = False
    normalized["counts_as_finding"] = False
    return normalized


def score_regenerated_hypothesis(h: dict[str, Any]) -> dict[str, Any]:
    """Score post-hoc regenerated hypotheses with stricter PoC-readiness checks.

    These rows remain hypotheses only. The score is used to decide whether local
    PoC scaffolding is worth attempting, not to promote anything to a finding.
    """
    normalized = normalize_regenerated_hypothesis(h)
    base = score_hypothesis(normalized)
    minimal = normalized.get("minimal_poc_idea") or normalized.get("minimal_poc_plan") or {}
    framework = str(minimal.get("framework") or normalized.get("framework") or "").lower()
    exploit_sequence = normalized.get("exploit_sequence")
    sequence_present = bool(exploit_sequence) if isinstance(exploit_sequence, list) else exploit_sequence_present(normalized)
    regenerated_checks = {
        "regenerated_schema": has_specific(normalized.get("hypothesis_id") or normalized.get("id")) and normalized.get("post_hoc_regression_only") is True,
        "exact_file_contract_function": has_specific(normalized.get("file_path")) and has_specific(normalized.get("contract")) and has_specific(normalized.get("function")),
        "concrete_affected_asset": has_specific(normalized.get("affected_asset")),
        "normal_attacker_or_role_labeled": has_specific(normalized.get("attacker_capabilities")),
        "ordered_exploit_sequence": sequence_present,
        "foundry_poc_idea": "foundry" in framework or poc_idea_present(normalized),
        "assertion_target": assertion_present(normalized),
        "kill_condition": kill_condition_present(normalized),
        "not_report_ready": normalized.get("state") == "HYPOTHESIS" and not bool(normalized.get("report_ready")),
    }
    missing_regenerated = [k for k, v in regenerated_checks.items() if not v]
    score = float(base["quality_score"])
    if missing_regenerated:
        score = min(score, 6.0)
    if not regenerated_checks["exact_file_contract_function"] or not regenerated_checks["ordered_exploit_sequence"]:
        score = min(score, 5.0)
    if not regenerated_checks["foundry_poc_idea"] or not regenerated_checks["assertion_target"]:
        score = min(score, 6.5)
    rounded = round(score, 2)
    overbroad_noise = bool(base["overbroad_noise"] or not regenerated_checks["exact_file_contract_function"] or rounded < 5.0)
    poc_ready = bool(rounded >= 7.0 and not overbroad_noise and regenerated_checks["foundry_poc_idea"] and regenerated_checks["assertion_target"] and regenerated_checks["kill_condition"])
    high_quality = bool(rounded >= 8.0 and poc_ready)
    merged_checks = {**base["checks"], **regenerated_checks}
    missing = list(dict.fromkeys(base.get("missing_quality_factors", []) + missing_regenerated))
    return {
        **base,
        "hypothesis_id": normalized.get("hypothesis_id") or normalized.get("id") or normalized.get("lead_id"),
        "case_id": normalized.get("case_id"),
        "pair_id": normalized.get("pair_id"),
        "version_kind": normalized.get("version_kind"),
        "quality_score": rounded,
        "checks": merged_checks,
        "missing_quality_factors": missing,
        "regenerated": True,
        "poc_ready": poc_ready,
        "high_quality": high_quality,
        "overbroad_noise": overbroad_noise,
        "counts_as_finding": False,
        "report_ready": False,
    }


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace"))


def _load_manifest(root: Path) -> dict[str, Any]:
    path = root / "patched_control_manifest.json"
    return _load_json(path) if path.exists() else {"pairs": []}


def _precision_dir(root: Path) -> Path:
    out = root / "scoring" / PRECISION_REGENERATION_DIR
    out.mkdir(parents=True, exist_ok=True)
    return out


def _load_regenerated_case(root: Path, pair_id: str, version_kind: str) -> dict[str, Any]:
    path = _precision_dir(root) / f"{pair_id}_{version_kind}_regenerated_hypotheses.json"
    return _load_json(path) if path.exists() else {"status": "MISSING", "hypotheses": []}


def score_regenerated_split(root: Path = PUBLIC_ROOT, *, split: str = "patched-controls") -> dict[str, Any]:
    manifest = _load_manifest(root)
    out = _precision_dir(root)
    cases: list[dict[str, Any]] = []
    all_scores: list[dict[str, Any]] = []
    for pair in manifest.get("pairs", []):
        pair_scores: list[dict[str, Any]] = []
        pair_cases: list[dict[str, Any]] = []
        for version_kind in ["vulnerable", "patched"]:
            payload = _load_regenerated_case(root, pair["pair_id"], version_kind)
            hypotheses = payload.get("hypotheses", [])
            scores = [score_regenerated_hypothesis(h) for h in hypotheses]
            pair_scores.extend(scores)
            pair_cases.append({"case_id": payload.get("case_id"), "version_kind": version_kind, "hypothesis_count": len(hypotheses), "scores": scores})
        quality = {
            "status": "PASS" if pair_scores else "BLOCKED",
            "pair_id": pair["pair_id"],
            "classification": "post_hoc_regression_only",
            "average_quality": round(sum(s["quality_score"] for s in pair_scores) / (len(pair_scores) or 1), 2),
            "high_quality_count": sum(1 for s in pair_scores if s["high_quality"]),
            "poc_ready_count": sum(1 for s in pair_scores if s["poc_ready"]),
            "overbroad_noise_count": sum(1 for s in pair_scores if s["overbroad_noise"]),
            "overbroad_noise_rate": round(sum(1 for s in pair_scores if s["overbroad_noise"]) / (len(pair_scores) or 1), 4),
            "scores": pair_scores,
        }
        (out / f"{pair['pair_id']}_quality_scores.json").write_text(json.dumps(quality, indent=2) + "\n")
        cases.append({"pair_id": pair["pair_id"], "status": quality["status"], "cases": pair_cases, "quality": quality})
        all_scores.extend(pair_scores)
    result = {
        "status": "PASS" if cases and all(c["status"] == "PASS" for c in cases) else "BLOCKED",
        "split": split,
        "classification": "post_hoc_regression_only",
        "hypothesis_count": len(all_scores),
        "average_hypothesis_quality_score": round(sum(s["quality_score"] for s in all_scores) / (len(all_scores) or 1), 2),
        "high_quality_hypothesis_count": sum(1 for s in all_scores if s["high_quality"]),
        "poc_ready_hypothesis_count": sum(1 for s in all_scores if s["poc_ready"]),
        "overbroad_noise_count": sum(1 for s in all_scores if s["overbroad_noise"]),
        "overbroad_noise_rate": round(sum(1 for s in all_scores if s["overbroad_noise"]) / (len(all_scores) or 1), 4),
        "quality_targets_met": bool(all_scores and round(sum(s["quality_score"] for s in all_scores) / len(all_scores), 2) >= 6.0 and sum(1 for s in all_scores if s["high_quality"]) >= 3 and sum(1 for s in all_scores if s["poc_ready"]) >= 3 and (sum(1 for s in all_scores if s["overbroad_noise"]) / len(all_scores)) <= 0.50),
        "production_readiness_changed": False,
        "cases": cases,
    }
    (out / "regenerated_hypothesis_quality_scores.json").write_text(json.dumps(result, indent=2) + "\n")
    summary_path = out / "precision_regeneration_summary.json"
    if summary_path.exists():
        summary = _load_json(summary_path)
        summary.update({
            "average_regenerated_hypothesis_quality": result["average_hypothesis_quality_score"],
            "high_quality_regenerated_hypothesis_count": result["high_quality_hypothesis_count"],
            "poc_ready_regenerated_hypothesis_count": result["poc_ready_hypothesis_count"],
            "overbroad_noise_rate": result["overbroad_noise_rate"],
            "quality_targets_met": result["quality_targets_met"],
            "production_readiness_changed": False,
        })
        summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    return result


def score_case(root: Path, case_id: str) -> dict[str, Any]:
    loaded = load_case_outputs(root, case_id)
    if loaded["status"] != "PASS":
        return {"status": "FAIL", "case_id": case_id, "reason": "frozen outputs unavailable", "loader": loaded}
    hypotheses = loaded["artifacts"]["hypotheses"].get("hypotheses", [])
    rows = [score_hypothesis(h) for h in hypotheses]
    avg = round(sum(r["quality_score"] for r in rows) / (len(rows) or 1), 2)
    return {"status": "PASS", "case_id": case_id, "hypothesis_count": len(rows), "average_hypothesis_quality_score": avg, "high_quality_hypothesis_count": sum(1 for r in rows if r["high_quality"]), "component_only_hypothesis_count": sum(1 for r in rows if r["component_only"]), "component_only_weak_leads": sum(1 for r in rows if r["component_only_weak_lead"]), "poc_ready_hypothesis_count": sum(1 for r in rows if r["poc_ready"]), "kill_ready_hypothesis_count": sum(1 for r in rows if r["kill_ready"]), "overbroad_noise_count": sum(1 for r in rows if r["overbroad_noise"]), "scores": rows}


def score_split(root: Path = PUBLIC_ROOT, *, split: str = "fresh-holdout") -> dict[str, Any]:
    cases = [score_case(root, cid) for cid in case_ids_for_split(root, split)]
    all_scores = [s for c in cases for s in c.get("scores", [])]
    result = {"status": "PASS" if cases and all(c["status"] == "PASS" for c in cases) else "BLOCKED", "split": split, "case_count": len(cases), "hypothesis_count": len(all_scores), "average_hypothesis_quality_score": round(sum(s["quality_score"] for s in all_scores) / (len(all_scores) or 1), 2), "high_quality_hypothesis_count": sum(1 for s in all_scores if s["high_quality"]), "component_only_hypothesis_count": sum(1 for s in all_scores if s["component_only"]), "component_only_weak_leads": sum(1 for s in all_scores if s["component_only_weak_lead"]), "poc_ready_hypothesis_count": sum(1 for s in all_scores if s["poc_ready"]), "kill_ready_hypothesis_count": sum(1 for s in all_scores if s["kill_ready"]), "overbroad_noise_count": sum(1 for s in all_scores if s["overbroad_noise"]), "cases": cases}
    out = root / "scoring" / "hypothesis_quality_scores.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Score frozen or regenerated hypotheses")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="fresh-holdout")
    p.add_argument("--frozen-only", action="store_true")
    p.add_argument("--regenerated", action="store_true", help="score post-hoc precision-regenerated patched-control hypotheses")
    args = p.parse_args(argv)
    result = score_regenerated_split(Path(args.root), split=args.split) if args.regenerated else score_split(Path(args.root), split=args.split)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
