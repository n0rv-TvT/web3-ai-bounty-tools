#!/usr/bin/env python3
"""Select one expected-finding-related hypothesis for precision repair."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from expected_aligned_repair_common import PUBLIC_ROOT, MATCH_RANK, REPAIR_RANK, base_result_flags, load_json, repair_dir, safe_id, source_path_for, write_json
from expected_related_hypothesis_inventory import build_inventory
from root_cause_precision_enricher import scan_source_facts


END_TO_END_SUPPORTED_FACT_PATTERNS = {"min_amount_equals_amount", "arbitrary_external_call"}


def source_fact_score(root: Path, split: str, row: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    source_file = str(row.get("related_file") or row.get("expected_source_file") or "")
    if not source_file:
        return 0, []
    scan = scan_source_facts(source_path_for(root, split, str(row.get("case_id")), source_file))
    facts = scan.get("facts", [])
    score = 0
    for fact in facts:
        if fact.get("pattern") == "min_amount_equals_amount" and any(t in str(row.get("expected_title") or row.get("expected_impact_type") or "").lower() for t in ["dust", "unstake", "redeem", "fail", "freeze"]):
            score += 6
        elif fact.get("pattern") == "arbitrary_external_call":
            score += 3
        elif fact.get("pattern") == "active_lifecycle_global_mutation":
            score += 1
        else:
            score += 1
    return score, facts


def row_priority(row: dict[str, Any], fact_score: int) -> tuple[int, int, int, int, int]:
    match_type = str(row.get("best_match_type") or "none")
    repairability = str(row.get("candidate_repairability") or "low")
    return (
        MATCH_RANK.get(match_type, 0),
        REPAIR_RANK.get(repairability, 0),
        fact_score,
        1 if row.get("related_source_facts_present") else 0,
        len(row.get("matched_fields") or []),
    )


def select_candidate(root: Path = PUBLIC_ROOT, *, split: str = "fresh-v6") -> dict[str, Any]:
    inv_path = repair_dir(root) / "expected_related_hypothesis_inventory.json"
    inventory = load_json(inv_path, {}) if inv_path.exists() else build_inventory(root, split=split)
    candidates = []
    rejected = []
    for row in inventory.get("rows", []):
        fact_score, facts = source_fact_score(root, split, row)
        reason = ""
        selectable = True
        if row.get("candidate_repairability") == "kill":
            selectable = False
            reason = "repairability marked kill"
        elif row.get("best_match_type") == "none" and not facts:
            selectable = False
            reason = "no related hypothesis and no source fact pattern"
        elif not (row.get("related_file") or row.get("expected_source_file")):
            selectable = False
            reason = "missing file source fact"
        elif row.get("best_match_type") == "weak" and not facts:
            selectable = False
            reason = "weak component signal lacks source-supported root-cause pattern"
        elif row.get("best_match_type") == "weak" and not any(f.get("pattern") in END_TO_END_SUPPORTED_FACT_PATTERNS for f in facts):
            selectable = False
            reason = "weak component signal lacks end-to-end supported repair pattern"
        annotated = {**row, "source_fact_score": fact_score, "source_fact_count": len(facts)}
        if selectable:
            candidates.append((row_priority(row, fact_score), annotated))
        else:
            rejected.append({"case_id": row.get("case_id"), "expected_finding_id": row.get("expected_finding_id"), "best_related_hypothesis_id": row.get("best_related_hypothesis_id"), "reason": reason})
    candidates.sort(key=lambda item: item[0], reverse=True)
    selected = candidates[0][1] if candidates else None
    for _prio, row in candidates[1:]:
        rejected.append({"case_id": row.get("case_id"), "expected_finding_id": row.get("expected_finding_id"), "best_related_hypothesis_id": row.get("best_related_hypothesis_id"), "reason": "lower priority than selected expected-related candidate"})

    if selected:
        candidate_id = safe_id(f"EXPECTED-ALIGNED-{selected.get('case_id')}-{selected.get('expected_finding_id')}-{selected.get('best_related_hypothesis_id') or 'source-fact'}")
        selected_candidate = {
            "candidate_id": candidate_id,
            "selected_expected_finding_id": selected.get("expected_finding_id"),
            "expected_finding_id": selected.get("expected_finding_id"),
            "expected_title": selected.get("expected_title"),
            "expected_severity": selected.get("expected_severity"),
            "expected_source_file": selected.get("expected_source_file"),
            "expected_component": selected.get("expected_component"),
            "expected_function": selected.get("expected_function"),
            "expected_bug_class": selected.get("expected_bug_class"),
            "expected_impact_type": selected.get("expected_impact_type"),
            "selected_hypothesis_id": selected.get("best_related_hypothesis_id"),
            "case_id": selected.get("case_id"),
            "match_type_before_repair": selected.get("best_match_type"),
            "repairability": selected.get("candidate_repairability"),
            "source_file": selected.get("related_file") or selected.get("expected_source_file"),
            "related_component": selected.get("related_component"),
            "related_file": selected.get("related_file"),
            "related_function": selected.get("related_function"),
            "related_lifecycle": selected.get("related_lifecycle"),
            "main_gap": selected.get("main_gap"),
            "source_fact_score": selected.get("source_fact_score"),
            "selection_reason": "selected expected-related weak/semantic signal with source-supported root-cause pattern; thresholds unchanged",
            "expected_finding_related": True,
            "counts_toward_readiness": False,
        }
    else:
        selected_candidate = {}

    result = {
        "status": "PASS" if selected else "EXPECTED_RELATED_REPAIR_INCONCLUSIVE",
        "split": split,
        "selected_expected_finding_id": selected_candidate.get("expected_finding_id"),
        "selected_hypothesis_id": selected_candidate.get("selected_hypothesis_id"),
        "case_id": selected_candidate.get("case_id"),
        "match_type_before_repair": selected_candidate.get("match_type_before_repair"),
        "repairability": selected_candidate.get("repairability"),
        "selection_reason": selected_candidate.get("selection_reason", "no expected-related candidate met repair starting criteria"),
        "selected_candidate": selected_candidate,
        "not_selected_reason_for_other_candidates": rejected,
        "thresholds_weakened": False,
        **base_result_flags(),
    }
    return write_json(repair_dir(root) / "expected_related_repair_selection.json", result)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Select an expected-aligned repair candidate")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="fresh-v6")
    p.add_argument("--frozen-only", action="store_true")
    args = p.parse_args(argv)
    result = select_candidate(Path(args.root), split=args.split)
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") in {"PASS", "EXPECTED_RELATED_REPAIR_INCONCLUSIVE"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
