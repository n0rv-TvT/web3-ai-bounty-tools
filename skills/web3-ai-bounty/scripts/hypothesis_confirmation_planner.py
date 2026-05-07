#!/usr/bin/env python3
"""Plan confirmation tasks for strong frozen hypotheses without promoting them."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from evidence_gap_analyzer import analyze_evidence_gaps
from frozen_output_loader import PUBLIC_ROOT, case_ids_for_split, load_case_outputs
from hypothesis_quality_scorer import score_hypothesis, score_regenerated_hypothesis
from poc_task_generator import foundry_poc_task


PRECISION_REGENERATION_DIR = "precision_regeneration"


def split_selection_path(root: Path, split: str) -> Path:
    safe_split = split.replace("-", "_")
    return root / "scoring" / f"{safe_split}_poc_candidate_selection.json"


def plan_for_hypothesis(h: dict[str, Any], *, regenerated: bool = False) -> dict[str, Any]:
    quality = score_regenerated_hypothesis(h) if regenerated else score_hypothesis(h)
    gaps = analyze_evidence_gaps(h)
    status = "NEEDS_POC"
    if quality["quality_score"] <= 4:
        status = "KILL_CANDIDATE"
    elif gaps["economic_proof_needed"]:
        status = "NEEDS_ECONOMIC_PROOF"
    elif gaps["needs_context"]:
        status = "NEEDS_CONTEXT"
    return {
        "hypothesis_id": h.get("id") or h.get("lead_id"),
        "case_id": h.get("case_id"),
        "confirmation_status": status,
        "quality_score": quality["quality_score"],
        "missing_evidence": gaps["missing_evidence"],
        "minimal_poc_plan": foundry_poc_task(h, gaps["missing_evidence"]),
        "economic_proof_needed": gaps["economic_proof_needed"],
        "patch_regression_task_needed": bool(h.get("patch_pair_id") or h.get("needs_patch_regression")),
        "manual_review_questions": ["Is the path reachable by a normal attacker?", "What exact invariant is violated?", "What assertion proves accepted bounty impact?", "What control test kills false positives?"],
        "report_ready": False,
        "counts_as_finding": False,
    }


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace"))


def _load_json_default(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace")) if path.exists() else default


def _precision_dir(root: Path) -> Path:
    out = root / "scoring" / PRECISION_REGENERATION_DIR
    out.mkdir(parents=True, exist_ok=True)
    return out


def _load_manifest(root: Path) -> dict[str, Any]:
    path = root / "patched_control_manifest.json"
    return _load_json(path) if path.exists() else {"pairs": []}


def _load_regenerated_case(root: Path, pair_id: str, version_kind: str) -> dict[str, Any]:
    path = _precision_dir(root) / f"{pair_id}_{version_kind}_regenerated_hypotheses.json"
    return _load_json(path) if path.exists() else {"status": "MISSING", "hypotheses": []}


def plan_split(root: Path = PUBLIC_ROOT, *, split: str = "fresh-holdout", min_quality: float = 7.0) -> dict[str, Any]:
    cases = []
    all_tasks = []
    for case_id in case_ids_for_split(root, split):
        loaded = load_case_outputs(root, case_id)
        if loaded["status"] != "PASS":
            cases.append({"case_id": case_id, "status": "FAIL", "reason": "frozen outputs unavailable"})
            continue
        tasks = []
        for h in loaded["artifacts"]["hypotheses"].get("hypotheses", []):
            h = dict(h, case_id=case_id)
            q = score_hypothesis(h)
            if q["quality_score"] >= min_quality:
                tasks.append(plan_for_hypothesis(h))
        all_tasks.extend(tasks)
        cases.append({"case_id": case_id, "status": "PASS", "hypotheses_selected_for_poc": len(tasks), "economic_proof_needed": sum(1 for t in tasks if t["economic_proof_needed"]), "kill_candidates": sum(1 for t in tasks if t["confirmation_status"] == "KILL_CANDIDATE"), "patch_regression_tasks": sum(1 for t in tasks if t["patch_regression_task_needed"]), "tasks": tasks})
    result = {"status": "PASS" if cases and all(c["status"] == "PASS" for c in cases) else "BLOCKED", "split": split, "task_count": len(all_tasks), "economic_proof_needed_count": sum(1 for t in all_tasks if t["economic_proof_needed"]), "kill_candidate_count": sum(1 for t in all_tasks if t["confirmation_status"] == "KILL_CANDIDATE"), "patch_regression_task_count": sum(1 for t in all_tasks if t["patch_regression_task_needed"]), "auto_promoted_report_ready": 0, "cases": cases}
    out = root / "scoring" / "hypothesis_confirmation_plan.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    return result


def plan_selected_candidates(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation") -> dict[str, Any]:
    selection = _load_json_default(split_selection_path(root, split), {"candidates": []})
    tasks = []
    for candidate in selection.get("selected_candidates") or selection.get("candidates") or []:
        h = {
            "id": candidate.get("hypothesis_id") or candidate.get("candidate_id"),
            "lead_id": candidate.get("hypothesis_id") or candidate.get("candidate_id"),
            "case_id": candidate.get("case_id"),
            "file_path": candidate.get("file_path"),
            "contract": candidate.get("contract"),
            "function": candidate.get("function"),
            "bug_class": candidate.get("bug_class"),
            "attacker_capabilities": candidate.get("attacker_capability"),
            "affected_asset": candidate.get("affected_asset"),
            "exploit_scenario": candidate.get("exploit_sequence") if isinstance(candidate.get("exploit_sequence"), str) else " then ".join(str(s) for s in (candidate.get("exploit_sequence") or [])),
            "impact": {"type": "requires-confirmation", "asset": candidate.get("affected_asset")},
            "external_evidence": [{"type": "selected_candidate", "file_path": candidate.get("file_path")}],
            "promotion_blockers": ["working_poc_required", "impact_assertion_required", "duplicate_intended_behavior_review_required"],
            "poc": {"idea": "Foundry local confirmation scaffold", "assertion": True, "kill_condition": candidate.get("kill_condition")},
            "kill_condition": candidate.get("kill_condition"),
            "state": "HYPOTHESIS",
            "severity_rationale": "fresh holdout hypothesis only; not a finding",
            "report_ready": False,
            "counts_as_finding": False,
        }
        task = plan_for_hypothesis(h)
        task.update({"candidate_id": candidate.get("candidate_id"), "split": split, "fresh_independent_holdout": True})
        tasks.append(task)
    result = {
        "status": "PASS" if tasks else "BLOCKED",
        "split": split,
        "mode": "selected-candidates",
        "classification": "fresh_holdout_confirmation_plan_not_finding",
        "task_count": len(tasks),
        "economic_proof_needed_count": sum(1 for t in tasks if t["economic_proof_needed"]),
        "kill_candidate_count": sum(1 for t in tasks if t["confirmation_status"] == "KILL_CANDIDATE"),
        "auto_promoted_report_ready": 0,
        "tasks": tasks,
        "answer_key_access": False,
        "writeup_access": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "report_ready_created": False,
        "production_readiness_changed": False,
    }
    out = root / "scoring" / f"{split.replace('-', '_')}_hypothesis_confirmation_plan.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    if split == "fresh-confirmation":
        (root / "scoring" / "fresh_confirmation_hypothesis_confirmation_plan.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def plan_regenerated_split(root: Path = PUBLIC_ROOT, *, split: str = "patched-controls", min_quality: float = 7.0) -> dict[str, Any]:
    manifest = _load_manifest(root)
    out = _precision_dir(root)
    pairs = []
    all_tasks = []
    for pair in manifest.get("pairs", []):
        pair_tasks = []
        for version_kind in ["vulnerable", "patched"]:
            payload = _load_regenerated_case(root, pair["pair_id"], version_kind)
            for h in payload.get("hypotheses", []):
                h = dict(h, case_id=h.get("case_id") or payload.get("case_id"), pair_id=pair["pair_id"], version_kind=version_kind)
                q = score_regenerated_hypothesis(h)
                if q["quality_score"] >= min_quality and version_kind == "vulnerable":
                    task = plan_for_hypothesis(h, regenerated=True)
                    task.update({"pair_id": pair["pair_id"], "version_kind": version_kind, "post_hoc_regression_only": True})
                    pair_tasks.append(task)
        all_tasks.extend(pair_tasks)
        pair_payload = {
            "status": "PASS",
            "pair_id": pair["pair_id"],
            "classification": "post_hoc_regression_only",
            "hypotheses_selected_for_poc": len(pair_tasks),
            "economic_proof_needed": sum(1 for t in pair_tasks if t["economic_proof_needed"]),
            "kill_candidates": sum(1 for t in pair_tasks if t["confirmation_status"] == "KILL_CANDIDATE"),
            "patch_regression_tasks": sum(1 for t in pair_tasks if t["patch_regression_task_needed"]),
            "tasks": pair_tasks,
        }
        pairs.append(pair_payload)
        (out / f"{pair['pair_id']}_confirmation_plan.json").write_text(json.dumps(pair_payload, indent=2) + "\n")
    result = {
        "status": "PASS" if pairs else "BLOCKED",
        "split": split,
        "classification": "post_hoc_regression_only",
        "task_count": len(all_tasks),
        "economic_proof_needed_count": sum(1 for t in all_tasks if t["economic_proof_needed"]),
        "kill_candidate_count": sum(1 for t in all_tasks if t["confirmation_status"] == "KILL_CANDIDATE"),
        "patch_regression_task_count": sum(1 for t in all_tasks if t["patch_regression_task_needed"]),
        "auto_promoted_report_ready": 0,
        "production_readiness_changed": False,
        "pairs": pairs,
    }
    (out / "regenerated_confirmation_plan.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Plan confirmation tasks for frozen or regenerated hypotheses")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="fresh-holdout")
    p.add_argument("--frozen-only", action="store_true")
    p.add_argument("--regenerated", action="store_true", help="use post-hoc precision-regenerated patched-control hypotheses")
    p.add_argument("--selected-candidates", action="store_true", help="plan from selected fresh holdout PoC candidates")
    args = p.parse_args(argv)
    if args.selected_candidates:
        result = plan_selected_candidates(Path(args.root), split=args.split)
    elif args.regenerated:
        result = plan_regenerated_split(Path(args.root), split=args.split)
    else:
        result = plan_split(Path(args.root), split=args.split)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
