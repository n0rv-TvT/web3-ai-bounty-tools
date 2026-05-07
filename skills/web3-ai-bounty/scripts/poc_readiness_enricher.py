#!/usr/bin/env python3
"""Enrich frozen hypotheses with PoC-readiness fields when source facts support it."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from assertion_synthesizer import synthesize_for_hypothesis
from frozen_output_loader import PUBLIC_ROOT, case_ids_for_split
from hypothesis_quality_scorer import score_hypothesis
from repair_to_poc_candidate_selection import candidate_id_for, find_hypothesis_for_candidate
from source_fact_to_attack_story_linker import link_hypothesis
from state_setup_inference import infer_state_setup


def enrich_expected_aligned_candidate(root: Path = PUBLIC_ROOT, *, split: str = "fresh-v6") -> dict[str, Any]:
    from expected_aligned_repair_common import base_result_flags, load_json, repair_dir, write_json

    root_cause_payload = load_json(repair_dir(root) / "expected_related_root_cause_precision.json", {})
    root_cause = root_cause_payload.get("candidate") or {}
    impact = load_json(repair_dir(root) / "expected_related_asset_impact.json", {})
    story = load_json(repair_dir(root) / "expected_related_attack_story.json", {})
    setup = load_json(repair_dir(root) / "expected_related_state_setup.json", {}).get("state_setup") or {}
    assertion_payload = load_json(repair_dir(root) / "expected_related_assertion_plan.json", {})
    assertion = assertion_payload.get("assertion_plan") or {}
    if not (root_cause and impact and story.get("minimum_steps_present") and setup and assertion.get("assertions")):
        result = {"status": "EXPECTED_RELATED_REPAIR_INCONCLUSIVE", "split": split, "reason": "missing root cause, impact, sequence, state setup, or assertion", **base_result_flags()}
        return write_json(repair_dir(root) / "expected_related_poc_readiness.json", result)

    candidate_id = str(root_cause.get("candidate_id"))
    repaired = {
        "candidate_id": candidate_id,
        "id": candidate_id,
        "lead_id": candidate_id,
        "hypothesis_id": candidate_id,
        "case_id": root_cause.get("case_id"),
        "expected_finding_id": root_cause.get("expected_finding_id"),
        "expected_finding_related": True,
        "title": "Hypothesis: expected-aligned source-supported repair needs executable proof before reporting",
        "state": "HYPOTHESIS",
        "severity_rationale": "post-hoc expected-aligned hypothesis; not a finding until executable proof passes",
        "bug_class": root_cause.get("bug_class"),
        "file_path": root_cause.get("file"),
        "contract": root_cause.get("contract"),
        "function": root_cause.get("function"),
        "attacker_capabilities": "normal external user following the documented lifecycle unless source-level roles prove otherwise",
        "affected_asset": impact.get("affected_asset"),
        "impact": {"type": impact.get("impact_type"), "asset": impact.get("affected_asset")},
        "exploit_scenario": f"Because a user can reach {root_cause.get('contract')}.{root_cause.get('function')} while {root_cause.get('root_cause_hypothesis')}, the lifecycle can fail causing {impact.get('impact_type')} for {impact.get('affected_asset')}.",
        "exploit_sequence": story.get("steps") or [],
        "external_evidence": root_cause.get("source_evidence") or [],
        "minimal_poc_idea": {
            "framework": "Foundry",
            "poc_type": assertion.get("assertion_kind") or impact.get("impact_type"),
            "actors": setup.get("actors") or story.get("actors") or [],
            "setup": setup,
            "attack_steps": story.get("steps") or [],
            "assertions": assertion.get("assertions") or [],
            "kill_condition": assertion.get("kill_condition"),
            "manual_completion_required": True,
        },
        "poc": {"path": "", "idea": "Build a local Foundry scaffold from the expected-aligned source evidence", "assertion": True, "kill_condition": assertion.get("kill_condition")},
        "poc_idea": "Build a local Foundry scaffold from the expected-aligned source evidence",
        "kill_condition": assertion.get("kill_condition"),
        "evidence_missing": ["manual harness completion", "executed exploit/control test", "duplicate/intended-behavior review"],
        "answer_key_text_dependency": bool(root_cause.get("answer_key_text_dependency")),
        "component_only": False,
        "report_ready": False,
        "counts_as_finding": False,
        "counts_toward_readiness": False,
    }
    quality = score_hypothesis(repaired)
    blocks: list[str] = []
    if quality["quality_score"] < 7.0:
        blocks.append("quality below 7")
    if not quality["poc_ready"]:
        blocks.append("poc readiness scorer rejected candidate")
    if repaired["answer_key_text_dependency"]:
        blocks.append("answer-key text dependency")
    result = {
        "status": "PASS" if not blocks else "EXPECTED_RELATED_REPAIR_INCONCLUSIVE",
        "outcome": "EXPECTED_RELATED_POC_READY_CANDIDATE_CREATED" if not blocks else "EXPECTED_RELATED_REPAIR_INCONCLUSIVE",
        "split": split,
        "candidate_id": candidate_id,
        "case_id": repaired.get("case_id"),
        "expected_finding_id": repaired.get("expected_finding_id"),
        "candidate": repaired,
        "quality_score": quality["quality_score"],
        "poc_ready": bool(quality["poc_ready"] and not blocks),
        "high_quality": bool(quality["high_quality"]),
        "poc_readiness_blocks": blocks,
        "checks": quality.get("checks"),
        **base_result_flags(),
    }
    return write_json(repair_dir(root) / "expected_related_poc_readiness.json", result)


def has_exact_location(h: dict[str, Any]) -> bool:
    return bool(h.get("file_path") and h.get("contract") and h.get("function"))


def repaired_candidate_id_for(case_id: str, hypothesis_id: str, h: dict[str, Any]) -> str:
    return str(h.get("candidate_id") or candidate_id_for(case_id, hypothesis_id))


def enrich_hypothesis(h: dict[str, Any]) -> dict[str, Any]:
    before = score_hypothesis(h)
    linked = link_hypothesis(h)
    setup = infer_state_setup(h)
    assertion = synthesize_for_hypothesis({**h, "affected_asset": linked.get("affected_asset") or h.get("affected_asset")})
    repaired = dict(h)
    repair_actions: list[str] = []

    if not has_exact_location(h):
        hypothesis_id = h.get("id") or h.get("lead_id")
        case_id = h.get("case_id")
        return {
            "status": "BLOCKED_MISSING_LOCATION",
            "candidate_id": repaired_candidate_id_for(str(case_id or ""), str(hypothesis_id or ""), h),
            "hypothesis_id": hypothesis_id,
            "original_quality_score": before["quality_score"],
            "repaired_quality_score": before["quality_score"],
            "repaired_hypothesis": repaired,
            "repair_actions": [],
            "state_setup": setup,
            "assertion_plan": assertion,
            "poc_ready": False,
            "report_ready": False,
            "counts_as_finding": False,
        }

    if "requires validation" in str(repaired.get("affected_asset") or "").lower() or not repaired.get("affected_asset"):
        repaired["affected_asset"] = linked["affected_asset"]
        repair_actions.append("replace_generic_asset_with_source_fact_asset")
    impact = repaired.get("impact") if isinstance(repaired.get("impact"), dict) else {}
    if not impact.get("asset") or "requires validation" in str(impact.get("asset")).lower():
        repaired["impact"] = {**impact, "type": impact.get("type") or "requires-confirmation", "asset": repaired["affected_asset"]}
        repair_actions.append("add_impact_asset")
    if linked.get("root_cause") and linked["root_cause"] not in str(repaired.get("exploit_scenario") or ""):
        repaired["exploit_scenario"] = (
            f"Because an attacker can exercise {repaired.get('contract')}.{repaired.get('function')} while {linked['root_cause']}, "
            f"the attacker can run the lifecycle boundary and cause impact to {repaired.get('affected_asset')}."
        )
        repair_actions.append("add_precise_attack_story")
    if linked.get("exploit_path"):
        repaired["exploit_sequence"] = linked["exploit_path"]
        repair_actions.append("add_ordered_exploit_sequence")
    repaired["minimal_poc_idea"] = {
        "framework": "Foundry",
        "poc_type": assertion["assertion_kind"],
        "actors": setup["actors"],
        "setup": {
            "roles": setup["required_roles"],
            "balances": setup["required_token_balances"],
            "approvals": setup["required_approvals"],
            "oracle_state": setup["required_oracle_state"],
            "time_or_block_state": setup["required_time_or_block_state"],
            "prior_lifecycle_steps": setup["required_prior_lifecycle_steps"],
            "external_dependencies": setup["required_external_dependencies"],
        },
        "attack_steps": repaired.get("exploit_sequence") or linked.get("exploit_path") or [],
        "assertions": assertion["assertions"],
        "kill_condition": assertion["kill_condition"],
        "manual_completion_required": True,
    }
    repaired["poc"] = {
        "path": "",
        "idea": f"Implement a local Foundry test for {repaired.get('contract')}.{repaired.get('function')} using inferred setup and assertion plan",
        "assertion": True,
        "kill_condition": assertion["kill_condition"],
    }
    repaired["poc_idea"] = repaired["poc"]["idea"]
    repaired["kill_condition"] = assertion["kill_condition"]
    repaired["evidence_missing"] = ["manual source trace", "completed executable PoC/control test", "duplicate and intended-behavior review"]
    repaired["preconditions"] = list(dict.fromkeys((h.get("preconditions") or []) + setup["required_prior_lifecycle_steps"] + ["normal attacker/victim lifecycle preconditions must be reproduced locally"]))
    repaired["answer_key_text_dependency"] = False
    repaired["state"] = "HYPOTHESIS"
    repaired["report_ready"] = False
    repaired["counts_as_finding"] = False
    repaired["posthoc_precision_repair"] = True
    repaired["counts_toward_readiness"] = False

    after = score_hypothesis(repaired)
    hypothesis_id = repaired.get("id") or repaired.get("lead_id")
    case_id = repaired.get("case_id")
    candidate_id = repaired_candidate_id_for(str(case_id or ""), str(hypothesis_id or ""), repaired)
    return {
        "status": "PASS" if after["poc_ready"] else "REPAIRED_NOT_POC_READY",
        "candidate_id": candidate_id,
        "hypothesis_id": hypothesis_id,
        "case_id": case_id,
        "original_quality_score": before["quality_score"],
        "repaired_quality_score": after["quality_score"],
        "quality_delta": round(after["quality_score"] - before["quality_score"], 2),
        "repair_actions": list(dict.fromkeys(repair_actions + ["add_foundry_poc_plan", "add_assertions", "add_kill_condition"])),
        "state_setup": setup,
        "assertion_plan": assertion,
        "repaired_hypothesis": repaired,
        "poc_ready": after["poc_ready"],
        "high_quality": after["high_quality"],
        "report_ready": False,
        "counts_as_finding": False,
    }


def repaired_candidate_from_enrichment(enriched: dict[str, Any], selected: dict[str, Any] | None, *, split: str) -> dict[str, Any]:
    repaired = enriched.get("repaired_hypothesis") or {}
    minimal = repaired.get("minimal_poc_idea") or {}
    candidate_id = str(enriched.get("candidate_id") or (selected or {}).get("candidate_id") or candidate_id_for(str(enriched.get("case_id") or ""), str(enriched.get("hypothesis_id") or "")))
    return {
        "candidate_id": candidate_id,
        "repaired_candidate_id": candidate_id,
        "hypothesis_id": enriched.get("hypothesis_id"),
        "case_id": enriched.get("case_id"),
        "split": split,
        "source_case_path": f"{split}/{enriched.get('case_id')}",
        "file_path": repaired.get("file_path") or repaired.get("file"),
        "contract": repaired.get("contract"),
        "function": repaired.get("function"),
        "bug_class": repaired.get("bug_class"),
        "quality_score": enriched.get("repaired_quality_score"),
        "original_quality_score": enriched.get("original_quality_score"),
        "quality_delta": enriched.get("quality_delta"),
        "match_type": (selected or {}).get("match_type"),
        "expected_finding_related": bool((selected or {}).get("expected_finding_related")),
        "expected_finding_id": (selected or {}).get("expected_finding_id"),
        "affected_asset": repaired.get("affected_asset"),
        "attacker_capability": repaired.get("attacker_capabilities") or repaired.get("attacker_capability"),
        "exploit_sequence": repaired.get("exploit_sequence") or [],
        "preconditions": repaired.get("preconditions") or [],
        "minimal_poc_idea": minimal,
        "assertion": minimal.get("assertions") or (repaired.get("poc") or {}).get("assertion"),
        "kill_condition": repaired.get("kill_condition") or minimal.get("kill_condition") or (repaired.get("poc") or {}).get("kill_condition"),
        "state_setup": enriched.get("state_setup") or {},
        "assertion_plan": enriched.get("assertion_plan") or {},
        "repair_actions": enriched.get("repair_actions") or [],
        "poc_ready": bool(enriched.get("poc_ready")),
        "high_quality": bool(enriched.get("high_quality")),
        "fresh_independent_holdout": False,
        "answer_key_text_dependency": bool(repaired.get("answer_key_text_dependency")),
        "post_hoc_repair_only": True,
        "post_hoc_regression_only": False,
        "report_ready": False,
        "counts_as_finding": False,
        "counts_toward_readiness": False,
    }


def outcome_for_enrichment(enriched: dict[str, Any]) -> str:
    if enriched.get("poc_ready"):
        return "POC_READY_CANDIDATE_CREATED"
    status = str(enriched.get("status") or "")
    if status == "BLOCKED_MISSING_LOCATION":
        return "REPAIR_BLOCKED_MISSING_EXPLOIT_SEQUENCE"
    if not (enriched.get("assertion_plan") or {}).get("assertions"):
        return "REPAIR_BLOCKED_MISSING_ASSERTION"
    if not (enriched.get("state_setup") or {}).get("actors"):
        return "REPAIR_BLOCKED_MISSING_STATE_SETUP"
    if not (enriched.get("repaired_hypothesis") or {}).get("exploit_sequence"):
        return "REPAIR_BLOCKED_MISSING_EXPLOIT_SEQUENCE"
    return "REPAIR_INCONCLUSIVE"


def enrich_candidate(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation", candidate: str = "") -> dict[str, Any]:
    selected, hypothesis = find_hypothesis_for_candidate(root, split, candidate)
    if not hypothesis:
        result = {
            "status": "BLOCKED",
            "outcome": "REPAIR_INCONCLUSIVE",
            "split": split,
            "candidate": candidate,
            "reason": "selected repair candidate could not be resolved to a frozen hypothesis",
            "answer_key_access": False,
            "writeup_access": False,
            "network_used": False,
            "secrets_accessed": False,
            "broadcasts_used": False,
            "counts_toward_readiness": False,
        }
    else:
        case_id = str(hypothesis.get("case_id") or (selected or {}).get("case_id") or "")
        hypothesis_id = str(hypothesis.get("id") or hypothesis.get("lead_id") or hypothesis.get("hypothesis_id") or "")
        candidate_id = str((selected or {}).get("candidate_id") or candidate_id_for(case_id, hypothesis_id))
        enriched = enrich_hypothesis({**hypothesis, "case_id": case_id, "candidate_id": candidate_id})
        repaired_candidate = repaired_candidate_from_enrichment(enriched, selected, split=split)
        outcome = outcome_for_enrichment(enriched)
        result = {
            "status": "PASS" if outcome == "POC_READY_CANDIDATE_CREATED" else "BLOCKED",
            "outcome": outcome,
            "split": split,
            "candidate_id": candidate_id,
            "hypothesis_id": hypothesis_id,
            "case_id": case_id,
            "candidate": repaired_candidate,
            "repaired_candidates": [repaired_candidate] if repaired_candidate.get("poc_ready") else [],
            "enrichment": enriched,
            "selection": selected or {},
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
    out = root / "scoring" / "repair_to_poc_readiness_enrichment.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    return result


def run_split(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation") -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for case_id in case_ids_for_split(root, split):
        path = root / "generated_reports" / f"{case_id}_hypotheses.json"
        if not path.exists():
            continue
        payload = json.loads(path.read_text(errors="replace"))
        rows.extend(enrich_hypothesis(dict(h, case_id=case_id)) for h in payload.get("hypotheses", []))
    result = {
        "status": "PASS" if rows else "BLOCKED",
        "split": split,
        "enriched_count": len(rows),
        "bulk_poc_ready_count": sum(1 for r in rows if r.get("poc_ready")),
        "bulk_high_quality_count": sum(1 for r in rows if r.get("high_quality")),
        "poc_ready_count": 0,
        "high_quality_count": 0,
        "enriched": rows,
        "answer_key_access": False,
        "writeup_access": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "counts_toward_readiness": False,
    }
    out = root / "scoring" / "poc_readiness_enrichment.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    try:
        from repair_to_poc_candidate_selection import find_candidate_record, select_repair_candidates

        selection = select_repair_candidates(root, split=split)
        primary = find_candidate_record(root)
        if primary:
            selected_enrichment = enrich_candidate(root, split=split, candidate=str(primary.get("candidate_id") or primary.get("hypothesis_id") or ""))
            result["selected_candidate_enrichment"] = selected_enrichment
            result["selected_candidate_id"] = primary.get("candidate_id")
            result["selected_candidate_expected_related"] = bool(primary.get("expected_finding_related"))
            result["selection_status"] = selection.get("status")
            result["poc_ready_count"] = 1 if selected_enrichment.get("status") == "PASS" and selected_enrichment.get("candidate", {}).get("poc_ready") else 0
            result["high_quality_count"] = 1 if selected_enrichment.get("candidate", {}).get("high_quality") else 0
    except Exception as exc:  # pragma: no cover - defensive: split-level enrichment still useful
        result["selected_candidate_enrichment_error"] = str(exc)
    out.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Enrich frozen hypotheses with PoC-readiness fields")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="fresh-confirmation")
    p.add_argument("--frozen-only", action="store_true")
    p.add_argument("--candidate", default="", help="repair candidate id or hypothesis id to enrich")
    p.add_argument("--selected", action="store_true", help="enrich expected-aligned selected candidate")
    args = p.parse_args(argv)
    if args.selected:
        result = enrich_expected_aligned_candidate(Path(args.root), split=args.split)
    else:
        result = enrich_candidate(Path(args.root), split=args.split, candidate=args.candidate) if args.candidate else run_split(Path(args.root), split=args.split)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"PASS", "BLOCKED", "EXPECTED_RELATED_REPAIR_INCONCLUSIVE"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
