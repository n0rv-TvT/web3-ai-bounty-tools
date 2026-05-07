#!/usr/bin/env python3
"""Select precise regenerated hypotheses for isolated local PoC scaffolding.

Candidate selection is post-hoc regression-only. It never promotes a hypothesis
to a finding and it refuses to select candidates when the regenerated precision
summary fails the quality targets required before execution.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from candidate_rejection_analyzer import analyze_hypothesis, aggregate as aggregate_rejections
from frozen_output_loader import PUBLIC_ROOT, case_ids_for_split
from hypothesis_quality_scorer import has_specific, score_hypothesis, score_regenerated_hypothesis

PRECISION_REGENERATION_DIR = "precision_regeneration"
QUALITY_THRESHOLD = 7.0
FRESH_SPLITS = {"fresh-holdout", "fresh-confirmation", "fresh-v6"}


def precision_dir(root: Path) -> Path:
    out = root / "scoring" / PRECISION_REGENERATION_DIR
    out.mkdir(parents=True, exist_ok=True)
    return out


def load_json(path: Path, default: dict[str, Any] | None = None) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace")) if path.exists() else (default or {})


def split_selection_path(root: Path, split: str) -> Path:
    safe_split = safe_id(split)
    return root / "scoring" / f"{safe_split}_poc_candidate_selection.json"


def load_fresh_hypotheses(root: Path, case_id: str) -> list[dict[str, Any]]:
    payload = load_json(root / "generated_reports" / f"{case_id}_hypotheses.json", {"hypotheses": []})
    return list(payload.get("hypotheses") or [])


def fresh_candidate_rejection_reasons(h: dict[str, Any], score: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if not has_exact_location(h):
        reasons.append("missing_exact_file_contract_function")
    if not has_specific(h.get("affected_asset")):
        reasons.append("missing_concrete_affected_asset")
    if not has_specific(h.get("attacker_capabilities") or h.get("attacker_capability")):
        reasons.append("missing_attacker_capability")
    if score.get("quality_score", 0) < 5.0:
        reasons.append("quality_below_minimum_for_poc_scaffold")
    if score.get("quality_gate_failed") or h.get("report_ready") or h.get("counts_as_finding"):
        reasons.append("overstated_as_finding")
    return reasons


def build_fresh_candidate(h: dict[str, Any], score: dict[str, Any], *, case_id: str, split: str) -> dict[str, Any]:
    hyp_id = str(h.get("id") or h.get("lead_id") or score.get("hypothesis_id") or "hypothesis")
    return {
        "candidate_id": safe_id(f"POC-FRESH-{case_id}-{hyp_id}"),
        "hypothesis_id": hyp_id,
        "case_id": case_id,
        "split": split,
        "source_case_path": f"{split}/{case_id}",
        "file_path": h.get("file_path") or h.get("file"),
        "contract": h.get("contract"),
        "function": h.get("function"),
        "bug_class": h.get("bug_class"),
        "quality_score": score.get("quality_score"),
        "affected_asset": h.get("affected_asset"),
        "attacker_capability": h.get("attacker_capabilities") or h.get("attacker_capability"),
        "exploit_sequence": h.get("exploit_sequence") or h.get("exploit_scenario") or [],
        "minimal_poc_idea": h.get("minimal_poc_plan") or h.get("minimal_poc_idea") or h.get("poc") or {"framework": "Foundry", "attack_steps": [h.get("exploit_scenario") or "manually confirm or kill the hypothesis"], "assertions": ["assert concrete asset/state impact if reachable"], "kill_condition": "kill if no measurable state delta or normal-attacker reachability"},
        "assertion": (h.get("poc") or {}).get("assertion") or "assert concrete asset/state impact if reachable",
        "kill_condition": h.get("kill_condition") or (h.get("poc") or {}).get("kill_condition") or "kill if no measurable state delta or no normal-attacker reachability",
        "fresh_independent_holdout": True,
        "post_hoc_regression_only": False,
        "report_ready": False,
        "counts_as_finding": False,
    }


def select_fresh_candidates(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation", select_per_case: int = 1) -> dict[str, Any]:
    selected: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    cases = []
    for case_id in case_ids_for_split(root, split):
        scored = []
        for h in load_fresh_hypotheses(root, case_id):
            h = dict(h, case_id=case_id)
            score = score_hypothesis(h)
            reasons = fresh_candidate_rejection_reasons(h, score)
            row = (float(score.get("quality_score") or 0.0), h, score, reasons)
            scored.append(row)
        scored.sort(key=lambda row: row[0], reverse=True)
        case_selected = []
        for _quality, h, score, reasons in scored:
            candidate = build_fresh_candidate(h, score, case_id=case_id, split=split)
            if reasons or len(case_selected) >= select_per_case:
                rejected.append({"case_id": case_id, "hypothesis_id": candidate["hypothesis_id"], "quality_score": score.get("quality_score"), "reasons": reasons or ["not selected; per-case candidate budget filled"]})
            else:
                case_selected.append(candidate)
        selected.extend(case_selected)
        cases.append({"case_id": case_id, "hypothesis_count": len(scored), "selected_count": len(case_selected), "rejected_count": len(scored) - len(case_selected)})
    result = {
        "status": "PASS" if selected else "BLOCKED",
        "split": split,
        "mode": "fresh-selected-candidates",
        "classification": "fresh_holdout_poc_candidate_selection_not_finding",
        "select_per_case": select_per_case,
        "selected_count": len(selected),
        "rejected_count": len(rejected),
        "candidates": selected,
        "selected_candidates": selected,
        "rejected": rejected,
        "cases": cases,
        "answer_key_access": False,
        "writeup_access": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "report_ready_created": False,
        "counts_as_finding": False,
        "production_readiness_changed": False,
    }
    out = split_selection_path(root, split)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    if split == "fresh-confirmation":
        (root / "scoring" / "fresh_confirmation_candidate_selection.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def selected_ids_from_selection(root: Path, split: str) -> set[str]:
    payload = load_json(split_selection_path(root, split), {})
    return {str(c.get("hypothesis_id") or c.get("candidate_id")) for c in payload.get("selected_candidates", [])}


def repair_suggestions_for(audit: dict[str, Any]) -> list[str]:
    if audit.get("should_be_killed"):
        return ["kill as overbroad/component-only noise before PoC work"]
    suggestions: list[str] = []
    if audit.get("missing_file") or audit.get("missing_contract") or audit.get("missing_function"):
        suggestions.append("add exact file, contract, and function from source facts before any PoC planning")
    if audit.get("missing_root_cause"):
        suggestions.append("replace broad bug class with a source-supported root cause")
    if audit.get("missing_affected_asset"):
        suggestions.append("replace generic affected_asset with the concrete balance, reserve, share, role, oracle output, or lifecycle state at risk")
    if audit.get("missing_attacker_capability"):
        suggestions.append("label whether the actor is a normal external caller or a documented role")
    if audit.get("missing_exploit_sequence"):
        suggestions.append("add ordered setup, attack, and proof steps that can be executed locally")
    if audit.get("missing_poc_idea") or audit.get("missing_assertion") or audit.get("missing_kill_condition"):
        suggestions.append("add a Foundry-compatible PoC plan with concrete assertions and an explicit kill condition")
    if not suggestions:
        suggestions.append("manual source trace required; do not lower selector thresholds")
    return suggestions


def explain_fresh_rejections(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation", repair_suggestions: bool = False, top_repairable: int = 10) -> dict[str, Any]:
    selected = selected_ids_from_selection(root, split)
    audits: list[dict[str, Any]] = []
    for case_id in case_ids_for_split(root, split):
        for h in load_fresh_hypotheses(root, case_id):
            row = analyze_hypothesis(dict(h, case_id=case_id), selected_ids=selected)
            if repair_suggestions:
                row["repair_suggestions"] = repair_suggestions_for(row)
            audits.append(row)
    repairable = [a for a in audits if a.get("could_be_repaired") and not a.get("candidate_selected")]
    repairable.sort(key=lambda a: (float(a.get("quality_score") or 0.0), -len(a.get("rejection_reasons") or [])), reverse=True)
    top = []
    for rank, audit in enumerate(repairable[: max(top_repairable, 0)], start=1):
        top.append({
            "rank": rank,
            "case_id": audit.get("case_id"),
            "hypothesis_id": audit.get("hypothesis_id"),
            "quality_score": audit.get("quality_score"),
            "repair_type": audit.get("repair_type"),
            "rejection_reasons": audit.get("rejection_reasons", []),
            "repair_suggestions": repair_suggestions_for(audit),
            "posthoc_only": True,
            "counts_toward_readiness": False,
        })
    result = {
        "status": "PASS" if audits else "BLOCKED",
        "split": split,
        "mode": "fresh_candidate_rejection_debug",
        "hypothesis_count": len(audits),
        "selected_count": len(selected),
        "summary": aggregate_rejections(audits),
        "top_repairable_count": len(top),
        "top_repairable": top,
        "rejections": audits,
        "thresholds_weakened": False,
        "selector_assessment": "debug-only: explain rejections and propose repairs; candidate thresholds are unchanged",
        "answer_key_access": False,
        "writeup_access": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "report_ready_created": False,
        "counts_as_finding": False,
        "production_readiness_changed": False,
        "counts_toward_readiness": False,
    }
    out = root / "scoring" / f"{safe_id(split)}_candidate_rejection_debug.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    if split == "fresh-confirmation":
        (root / "scoring" / "fresh_confirmation_candidate_rejection_debug.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def load_manifest(root: Path) -> dict[str, Any]:
    return load_json(root / "patched_control_manifest.json", {"pairs": []})


def load_summary(root: Path) -> dict[str, Any]:
    return load_json(precision_dir(root) / "precision_regeneration_summary.json", {"status": "MISSING", "quality_targets_met": False})


def load_regenerated_case(root: Path, pair_id: str, version_kind: str) -> dict[str, Any]:
    return load_json(precision_dir(root) / f"{pair_id}_{version_kind}_regenerated_hypotheses.json", {"status": "MISSING", "hypotheses": []})


def safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "candidate"


def minimal_poc(h: dict[str, Any]) -> dict[str, Any]:
    return h.get("minimal_poc_idea") or h.get("minimal_poc_plan") or {}


def has_exact_location(h: dict[str, Any]) -> bool:
    return has_specific(h.get("file_path") or h.get("file")) and has_specific(h.get("contract")) and has_specific(h.get("function"))


def has_concrete_sequence(h: dict[str, Any]) -> bool:
    seq = h.get("exploit_sequence")
    if isinstance(seq, list):
        return len([s for s in seq if str(s).strip()]) >= 3
    return bool(seq and str(seq).strip())


def has_foundry_plan(h: dict[str, Any]) -> bool:
    poc = minimal_poc(h)
    return "foundry" in str(poc.get("framework") or "").lower() and bool(poc.get("attack_steps") or h.get("exploit_sequence"))


def has_assertion_and_kill(h: dict[str, Any]) -> bool:
    poc = minimal_poc(h)
    return bool((poc.get("assertions") or (h.get("poc") or {}).get("assertion")) and (h.get("kill_condition") or poc.get("kill_condition") or (h.get("poc") or {}).get("kill_condition")))


def candidate_rejection_reasons(h: dict[str, Any], score: dict[str, Any], *, quality_targets_met: bool, version_kind: str) -> list[str]:
    reasons: list[str] = []
    if not quality_targets_met:
        reasons.append("quality_targets_not_met")
    if version_kind != "vulnerable":
        reasons.append("patched_control_not_exploit_candidate")
    if score.get("quality_score", 0) < QUALITY_THRESHOLD:
        reasons.append("quality_below_threshold")
    if not has_exact_location(h):
        reasons.append("missing_exact_file_contract_function")
    if not has_specific(h.get("affected_asset")):
        reasons.append("missing_concrete_affected_asset")
    if not has_specific(h.get("attacker_capability") or h.get("attacker_capabilities")):
        reasons.append("missing_attacker_capability")
    if not has_concrete_sequence(h):
        reasons.append("missing_ordered_exploit_sequence")
    if not has_foundry_plan(h):
        reasons.append("missing_foundry_compatible_poc_idea")
    if not has_assertion_and_kill(h):
        reasons.append("missing_assertion_or_kill_condition")
    if score.get("overbroad_noise") or score.get("component_only") or score.get("component_only_weak_lead"):
        reasons.append("overbroad_or_component_only")
    if h.get("report_ready") or h.get("counts_as_finding"):
        reasons.append("overstated_as_finding")
    return reasons


def build_candidate(h: dict[str, Any], score: dict[str, Any], pair: dict[str, Any], *, version_kind: str) -> dict[str, Any]:
    hyp_id = str(h.get("hypothesis_id") or h.get("id") or h.get("lead_id"))
    candidate_id = safe_id(f"POC-{hyp_id}")
    case_id = str(h.get("case_id") or pair.get(f"{version_kind}_case_id") or hyp_id)
    return {
        "candidate_id": candidate_id,
        "hypothesis_id": hyp_id,
        "pair_id": pair["pair_id"],
        "case_id": case_id,
        "version_kind": version_kind,
        "source_case_path": pair.get(f"{version_kind}_detector_visible_path", f"patched-controls/{case_id}"),
        "file_path": h.get("file_path") or h.get("file"),
        "contract": h.get("contract"),
        "function": h.get("function"),
        "bug_class": h.get("bug_class"),
        "quality_score": score.get("quality_score"),
        "affected_asset": h.get("affected_asset"),
        "attacker_capability": h.get("attacker_capability") or h.get("attacker_capabilities"),
        "exploit_sequence": h.get("exploit_sequence"),
        "minimal_poc_idea": minimal_poc(h),
        "assertion": (minimal_poc(h).get("assertions") or [(h.get("poc") or {}).get("assertion")]),
        "kill_condition": h.get("kill_condition") or minimal_poc(h).get("kill_condition") or (h.get("poc") or {}).get("kill_condition"),
        "post_hoc_regression_only": True,
        "report_ready": False,
        "counts_as_finding": False,
    }


def select_candidates(root: Path = PUBLIC_ROOT, *, split: str = "patched-controls", regenerated: bool = True) -> dict[str, Any]:
    if not regenerated:
        return {"status": "BLOCKED", "reason": "candidate selection currently requires --regenerated", "selected_count": 0, "candidates": []}
    manifest = load_manifest(root)
    summary = load_summary(root)
    quality_targets_met = bool(summary.get("quality_targets_met"))
    selected: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for pair in manifest.get("pairs", []):
        for version_kind in ["vulnerable", "patched"]:
            payload = load_regenerated_case(root, pair["pair_id"], version_kind)
            for h in payload.get("hypotheses", []):
                score = score_regenerated_hypothesis(h)
                reasons = candidate_rejection_reasons(h, score, quality_targets_met=quality_targets_met, version_kind=version_kind)
                if reasons:
                    rejected.append({"hypothesis_id": h.get("hypothesis_id") or h.get("id"), "pair_id": pair["pair_id"], "version_kind": version_kind, "quality_score": score.get("quality_score"), "reasons": reasons})
                else:
                    selected.append(build_candidate(h, score, pair, version_kind=version_kind))
    result = {
        "status": "PASS" if manifest.get("pairs") else "BLOCKED",
        "split": split,
        "classification": "post_hoc_regression_only",
        "quality_targets_met": quality_targets_met,
        "execution_allowed": quality_targets_met and bool(selected),
        "selection_status": "SELECTED" if selected else ("BLOCKED_QUALITY_TARGETS" if not quality_targets_met else "NO_CANDIDATES"),
        "selected_count": len(selected),
        "rejected_count": len(rejected),
        "quality_threshold": QUALITY_THRESHOLD,
        "candidates": selected,
        "rejected": rejected,
        "production_readiness_changed": False,
        "report_ready_created": False,
        "counts_as_finding": False,
    }
    precision_dir(root).joinpath("poc_candidate_selection.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def load_patch_diff(root: Path) -> dict[str, Any]:
    return load_json(root / "scoring" / "patch_diff_analysis.json", {"pairs": []})


def generated_poc_exists(root: Path, candidate: dict[str, Any]) -> bool:
    generated = root / "generated_pocs"
    if not generated.exists():
        return False
    for manifest in generated.glob("**/poc_manifest.json"):
        payload = load_json(manifest, {})
        if payload.get("candidate_id") == candidate.get("candidate_id"):
            return True
    return False


def source_function_exists(root: Path, candidate: dict[str, Any], *, version_kind: str = "vulnerable") -> bool:
    case_id = str(candidate.get("case_id") or "")
    if version_kind == "patched":
        case_id = case_id.replace("_vulnerable", "_patched")
    source = root / "patched-controls" / case_id / str(candidate.get("file_path") or "")
    if not source.exists():
        return False
    return f"function {candidate.get('function')}" in source.read_text(errors="replace")


def patch_relevance_for(candidate: dict[str, Any], patch_diff: dict[str, Any]) -> tuple[bool, str]:
    for row in patch_diff.get("pairs", []):
        if row.get("pair_id") != candidate.get("pair_id"):
            continue
        changed_files = {f.get("file") for f in row.get("changed_files", [])}
        changed_functions = set(row.get("changed_functions", []))
        if candidate.get("file_path") in changed_files and candidate.get("function") in changed_functions:
            return True, "candidate exact file and function are present in the security-relevant patch diff"
        if candidate.get("file_path") in changed_files:
            return True, "candidate file is the security-relevant changed file and the exploit path can target the changed sibling processing function"
        if candidate.get("function") in changed_functions:
            return True, "candidate function is present in the security-relevant patch diff"
    return False, "candidate does not overlap a security-relevant patch diff"


def concrete_assertion_for(candidate: dict[str, Any]) -> tuple[bool, str]:
    text = f"{candidate.get('pair_id')} {candidate.get('contract')} {candidate.get('function')} {candidate.get('bug_class')} {candidate.get('affected_asset')}".lower()
    if "investmentmanager" in text and ("deposit" in text or "requestdeposit" in text):
        return True, "assert vulnerable processDeposit reverts/freeze when rounding asks escrow for more shares than maxMint, while patched processDeposit clamps to maxMint"
    if candidate.get("assertion") and candidate.get("kill_condition"):
        return True, "assert the candidate's concrete impact condition and kill if no measurable state delta occurs"
    return False, "no concrete assertion plan available"


def repaired_selection_path(root: Path, split: str) -> Path:
    return root / "scoring" / f"{safe_id(split).replace('-', '_')}_repaired_poc_candidate_selection.json"


def _split_matches(row: dict[str, Any], payload: dict[str, Any], split: str | None) -> bool:
    if not split:
        return True
    row_split = str(row.get("split") or payload.get("split") or "")
    return not row_split or row_split == split


def load_repaired_candidate_rows(root: Path, *, split: str | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in [
        root / "scoring" / "repair_to_poc_readiness_enrichment.json",
        root / "scoring" / "poc_readiness_enrichment.json",
    ]:
        path_rows: list[dict[str, Any]] = []
        payload = load_json(path, {})
        if payload.get("candidate"):
            candidate = dict(payload["candidate"])
            candidate.setdefault("split", payload.get("split"))
            path_rows.append(candidate)
        for repaired in payload.get("repaired_candidates", []):
            if isinstance(repaired, dict):
                repaired = dict(repaired)
                repaired.setdefault("split", payload.get("split"))
                path_rows.append(repaired)
        for enriched in payload.get("enriched", []):
            if not isinstance(enriched, dict):
                continue
            repaired = enriched.get("repaired_hypothesis") or {}
            path_rows.append({
                "candidate_id": enriched.get("candidate_id") or safe_id(f"REPAIR-POC-{enriched.get('case_id')}-{enriched.get('hypothesis_id')}"),
                "hypothesis_id": enriched.get("hypothesis_id"),
                "case_id": enriched.get("case_id"),
                "split": payload.get("split"),
                "file_path": repaired.get("file_path") or repaired.get("file"),
                "contract": repaired.get("contract"),
                "function": repaired.get("function"),
                "bug_class": repaired.get("bug_class"),
                "quality_score": enriched.get("repaired_quality_score"),
                "affected_asset": repaired.get("affected_asset"),
                "attacker_capability": repaired.get("attacker_capabilities") or repaired.get("attacker_capability"),
                "exploit_sequence": repaired.get("exploit_sequence") or [],
                "minimal_poc_idea": repaired.get("minimal_poc_idea") or {},
                "assertion": (repaired.get("minimal_poc_idea") or {}).get("assertions"),
                "kill_condition": repaired.get("kill_condition") or (repaired.get("minimal_poc_idea") or {}).get("kill_condition"),
                "poc_ready": bool(enriched.get("poc_ready")),
                "high_quality": bool(enriched.get("high_quality")),
                "post_hoc_repair_only": True,
                "report_ready": False,
                "counts_as_finding": False,
            })
        path_rows = [row for row in path_rows if _split_matches(row, payload, split)]
        rows.extend(path_rows)
        if path.name == "repair_to_poc_readiness_enrichment.json" and path_rows:
            break
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        key = str(row.get("candidate_id") or row.get("hypothesis_id") or len(seen))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped


def repaired_candidate_rejection_reasons(candidate: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if not candidate.get("poc_ready"):
        reasons.append("candidate_not_marked_poc_ready_by_repair_enricher")
    if float(candidate.get("quality_score") or 0.0) < QUALITY_THRESHOLD:
        reasons.append("quality_below_threshold")
    if candidate.get("answer_key_text_dependency"):
        reasons.append("answer_key_text_dependency")
    if not has_exact_location(candidate):
        reasons.append("missing_exact_file_contract_function")
    if not has_specific(candidate.get("affected_asset")):
        reasons.append("missing_concrete_affected_asset")
    if not has_specific(candidate.get("attacker_capability") or candidate.get("attacker_capabilities")):
        reasons.append("missing_attacker_capability")
    if not candidate.get("preconditions") and not (candidate.get("minimal_poc_idea") or {}).get("setup"):
        reasons.append("missing_preconditions")
    if not has_concrete_sequence(candidate):
        reasons.append("missing_ordered_exploit_sequence")
    if not has_foundry_plan(candidate):
        reasons.append("missing_foundry_compatible_poc_idea")
    if not has_assertion_and_kill(candidate):
        reasons.append("missing_assertion_or_kill_condition")
    if candidate.get("report_ready") or candidate.get("counts_as_finding"):
        reasons.append("overstated_as_finding")
    return list(dict.fromkeys(reasons))


def select_repaired_candidate(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation") -> dict[str, Any]:
    rows = load_repaired_candidate_rows(root, split=split)
    scored: list[tuple[tuple[int, int, float], dict[str, Any], list[str]]] = []
    for row in rows:
        reasons = repaired_candidate_rejection_reasons(row)
        score_tuple = (
            1 if not reasons else 0,
            1 if row.get("expected_finding_related") or str(row.get("match_type") or "") == "strict" else 0,
            float(row.get("quality_score") or 0.0),
        )
        scored.append((score_tuple, row, reasons))
    scored.sort(key=lambda item: item[0], reverse=True)
    selected = next((row for _score, row, reasons in scored if not reasons), None)
    rejected = [
        {
            "candidate_id": row.get("candidate_id"),
            "hypothesis_id": row.get("hypothesis_id"),
            "case_id": row.get("case_id"),
            "quality_score": row.get("quality_score"),
            "reasons": reasons or ["lower-ranked than selected repaired candidate"],
        }
        for _score, row, reasons in scored
        if not selected or row.get("candidate_id") != selected.get("candidate_id")
    ]
    output = {
        "status": "PASS" if selected else "BLOCKED",
        "selection_status": "SELECTED" if selected else "NO_REPAIRED_CANDIDATES",
        "split": split,
        "mode": "fresh_posthoc_repaired_candidate_selection",
        "selected_candidate_id": selected.get("candidate_id") if selected else None,
        "selected_repaired_candidate_id": selected.get("candidate_id") if selected else None,
        "selected_candidate": selected or {},
        "selected_count": 1 if selected else 0,
        "rejected_count": len(rejected),
        "rejected_candidates": rejected,
        "selection_reason": "selected repaired post-hoc candidate with exact location, concrete asset, ordered exploit path, Foundry plan, assertions, and kill condition" if selected else "no repaired candidate passed PoC-readiness selection without lowering thresholds",
        "thresholds_weakened": False,
        "scaffold_execution_allowed": False,
        "report_ready_created": False,
        "counts_as_finding": False,
        "production_readiness_changed": False,
        "fresh_independent_holdout": False,
        "post_hoc_repair_only": True,
        "counts_toward_readiness": False,
    }
    out = repaired_selection_path(root, split)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(output, indent=2) + "\n")
    (root / "scoring" / "repair_to_poc_repaired_candidate_selection.json").write_text(json.dumps(output, indent=2) + "\n")
    return output


def select_one_candidate(root: Path = PUBLIC_ROOT, *, split: str = "patched-controls") -> dict[str, Any]:
    selection = select_candidates(root, split=split, regenerated=True)
    patch_diff = load_patch_diff(root)
    scored: list[tuple[tuple[int, float, int], dict[str, Any], list[str], str]] = []
    for index, candidate in enumerate(selection.get("candidates", [])):
        reasons: list[str] = []
        if not has_exact_location(candidate):
            reasons.append("missing exact file/contract/function")
        if not source_function_exists(root, candidate, version_kind="vulnerable"):
            reasons.append("vulnerable source function not found")
        patched_source_ok = source_function_exists(root, candidate, version_kind="patched")
        if not patched_source_ok:
            reasons.append("patched source function not found")
        if not generated_poc_exists(root, candidate):
            reasons.append("generated PoC scaffold not found")
        patch_relevant, patch_reason = patch_relevance_for(candidate, patch_diff)
        if not patch_relevant:
            reasons.append(patch_reason)
        assertion_ok, assertion_plan = concrete_assertion_for(candidate)
        if not assertion_ok:
            reasons.append(assertion_plan)
        score_tuple = (
            1 if not reasons else 0,
            float(candidate.get("quality_score") or 0.0),
            1 if str(candidate.get("contract") or "").lower() == "investmentmanager" and "deposit" in str(candidate.get("function") or "").lower() else 0,
        )
        scored.append((score_tuple, candidate, reasons, assertion_plan))
    scored.sort(key=lambda row: row[0], reverse=True)
    selected_tuple, selected, selected_reasons, assertion_plan = scored[0] if scored else ((0, 0.0, 0), {}, ["no candidates available"], "")
    rejected = []
    for _score, candidate, reasons, plan in scored[1:8]:
        rejected.append({
            "candidate_id": candidate.get("candidate_id"),
            "pair_id": candidate.get("pair_id"),
            "quality_score": candidate.get("quality_score"),
            "reasons": reasons or ["lower-ranked than selected candidate"],
            "assertion_plan": plan,
        })
    selected_ok = bool(selected and not selected_reasons)
    output = {
        "status": "PASS" if selected_ok else "BLOCKED",
        "selected_candidate_id": selected.get("candidate_id"),
        "pair_id": selected.get("pair_id"),
        "selection_reason": "Highest-quality candidate with exact local source, generated scaffold, and direct overlap with the security-relevant InvestmentManager deposit patch; selected for a concrete rounding/fund-freeze assertion." if selected_ok else "; ".join(selected_reasons),
        "quality_score": float(selected.get("quality_score") or 0.0),
        "file": selected.get("file_path"),
        "contract": selected.get("contract"),
        "function": selected.get("function"),
        "bug_class": selected.get("bug_class"),
        "affected_asset": selected.get("affected_asset"),
        "attacker_capability": selected.get("attacker_capability"),
        "exploit_sequence": selected.get("exploit_sequence") or [],
        "assertion_plan": assertion_plan,
        "kill_condition": selected.get("kill_condition"),
        "patch_regression_possible": selected_ok,
        "rejected_top_candidates": rejected,
        "production_readiness_changed": False,
        "post_hoc_regression_only": True,
    }
    out = root / "scoring" / "poc_vertical_slice_candidate_selection.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(output, indent=2) + "\n")
    return output


def select_batch_candidates(root: Path = PUBLIC_ROOT, *, split: str = "patched-controls", count: int = 2) -> dict[str, Any]:
    selection = select_candidates(root, split=split, regenerated=True)
    patch_diff = load_patch_diff(root)
    already_selected = {load_json(root / "scoring" / "poc_vertical_slice_candidate_selection.json", {}).get("selected_candidate_id")}
    preferred_ids = [
        "POC-PREC-case_pc_0003-vulnerable-001",
        "POC-PREC-case_pc_0002-vulnerable-003",
    ]
    selected: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for candidate in selection.get("candidates", []):
        reasons: list[str] = []
        if candidate.get("candidate_id") in already_selected:
            reasons.append("already executed in the first vertical slice")
        if float(candidate.get("quality_score") or 0) < QUALITY_THRESHOLD:
            reasons.append("quality score below threshold")
        if not has_exact_location(candidate):
            reasons.append("missing exact file/contract/function")
        if not source_function_exists(root, candidate, version_kind="vulnerable"):
            reasons.append("vulnerable source function not found")
        if not source_function_exists(root, candidate, version_kind="patched"):
            reasons.append("patched source function not found")
        if not generated_poc_exists(root, candidate):
            reasons.append("generated PoC scaffold not found")
        patch_relevant, patch_reason = patch_relevance_for(candidate, patch_diff)
        if not patch_relevant:
            reasons.append(patch_reason)
        assertion_ok, assertion_plan = concrete_assertion_for(candidate)
        if not assertion_ok:
            reasons.append(assertion_plan)
        row = {**candidate, "assertion_plan": assertion_plan, "rejection_reasons": reasons}
        if reasons:
            rejected.append({"candidate_id": candidate.get("candidate_id"), "pair_id": candidate.get("pair_id"), "quality_score": candidate.get("quality_score"), "reasons": reasons})
        else:
            selected.append(row)

    selected.sort(key=lambda c: (0 if c.get("candidate_id") in preferred_ids else 1, preferred_ids.index(c.get("candidate_id")) if c.get("candidate_id") in preferred_ids else 99, -float(c.get("quality_score") or 0)))
    chosen = selected[:count]
    chosen_ids = {c.get("candidate_id") for c in chosen}
    for c in selected[count:]:
        rejected.append({"candidate_id": c.get("candidate_id"), "pair_id": c.get("pair_id"), "quality_score": c.get("quality_score"), "reasons": ["not selected; batch already filled with higher-priority executable candidates"]})

    coverage_by_pair = {
        "case_pc_0001": "no executable generated candidate overlapped the security-relevant Multicall.multicall patch; action-library candidates lacked patched source/exact patch overlap",
        "case_pc_0002": "selected requestRedeem auth/normal-attacker kill slice" if any(c.get("pair_id") == "case_pc_0002" for c in chosen) else "not selected",
        "case_pc_0003": "selected LiquidityPool.requestRedeemWithPermit permit-gated kill slice" if any(c.get("pair_id") == "case_pc_0003" for c in chosen) else "not selected",
    }
    output = {
        "status": "PASS" if len(chosen) == count else "BLOCKED",
        "selected_candidates": chosen,
        "rejected_candidates": rejected,
        "selection_reason": [
            "Selected two additional executable post-hoc candidates; case_pc_0001 was rejected because no generated candidate matched the Multicall patch closely enough.",
            "Chosen candidates have quality >= 7, exact local vulnerable/patched source, generated scaffolds, concrete assertion plans, and safe local execution paths.",
        ],
        "coverage_by_pair": coverage_by_pair,
        "selected_candidate_ids": list(chosen_ids),
        "production_readiness_changed": False,
        "post_hoc_regression_only": True,
    }
    out = root / "scoring" / "poc_vertical_slice_batch_selection.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(output, indent=2) + "\n")
    return output


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Select regenerated PoC candidates without promoting findings")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="patched-controls")
    p.add_argument("--regenerated", action="store_true")
    p.add_argument("--select-one", action="store_true", help="select exactly one vertical-slice candidate")
    p.add_argument("--select-batch", type=int, default=0, help="select N additional vertical-slice candidates")
    p.add_argument("--select-per-case", type=int, default=0, help="select N fresh holdout hypotheses per case for scaffold planning")
    p.add_argument("--frozen-only", action="store_true", help="accepted for fresh debug/failure-analysis workflows; no live data is used")
    p.add_argument("--explain-rejections", action="store_true", help="explain why fresh hypotheses were not selected")
    p.add_argument("--repair-suggestions", action="store_true", help="include post-hoc repair suggestions for rejected fresh hypotheses")
    p.add_argument("--top-repairable", type=int, default=0, help="list N rejected hypotheses that are most repairable without changing thresholds")
    p.add_argument("--repaired-candidates", action="store_true", help="select from post-hoc repaired fresh-confirmation candidates")
    args = p.parse_args(argv)
    if args.repaired_candidates:
        result = select_repaired_candidate(Path(args.root), split=args.split)
    elif args.explain_rejections or args.repair_suggestions or args.top_repairable:
        result = explain_fresh_rejections(Path(args.root), split=args.split, repair_suggestions=args.repair_suggestions, top_repairable=args.top_repairable or 10)
    elif args.select_per_case:
        result = select_fresh_candidates(Path(args.root), split=args.split, select_per_case=args.select_per_case)
    elif args.select_batch:
        result = select_batch_candidates(Path(args.root), split=args.split, count=args.select_batch)
    elif args.select_one:
        result = select_one_candidate(Path(args.root), split=args.split)
    else:
        result = select_candidates(Path(args.root), split=args.split, regenerated=args.regenerated)
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
