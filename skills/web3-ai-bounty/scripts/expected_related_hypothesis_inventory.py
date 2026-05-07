#!/usr/bin/env python3
"""Inventory expected findings and their frozen related hypotheses.

Weak matches are recorded only as repair starting points. They are never counted
as detections or findings.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from expected_aligned_repair_common import (
    PUBLIC_ROOT,
    base_result_flags,
    expected_rows_for_split,
    find_hypothesis,
    gap_by_expected,
    hypothesis_id,
    load_frozen_manual_items,
    match_for,
    repair_dir,
    score_case_by_id,
    write_json,
)


def related_manual_id(manual_items: list[dict[str, Any]], hyp_id: str) -> str:
    for item in manual_items:
        ids = {hypothesis_id(item), str(item.get("lead_id") or "")}
        if hyp_id and hyp_id in ids:
            return hypothesis_id(item)
    return ""


def repairability(match_type: str, gap: dict[str, Any], h: dict[str, Any] | None) -> str:
    if h is None and not gap.get("related_source_fact"):
        return "low"
    if not h and gap.get("related_source_fact"):
        return "low"
    if h and not (h.get("file_path") and h.get("contract") and h.get("function")):
        return "kill"
    if match_type in {"strict", "semantic"}:
        return "high"
    if match_type == "weak" and gap.get("related_source_fact"):
        return "medium"
    if gap.get("related_asset_flow") or gap.get("related_attack_surface_entry"):
        return "low"
    return "kill"


def main_gap_for(match_type: str, gap: dict[str, Any], h: dict[str, Any] | None) -> str:
    if match_type == "none" and not gap.get("related_source_fact"):
        return "NO_RELATED_HYPOTHESIS"
    if h and not h.get("affected_asset"):
        return "MISSING_ASSET"
    if h and not h.get("exploit_sequence"):
        return "MISSING_EXPLOIT_SEQUENCE"
    if match_type == "weak":
        return gap.get("main_gap") or "ROOT_CAUSE_TOO_VAGUE"
    return gap.get("main_gap") or "HUMAN_CONTEXT_REQUIRED"


def build_inventory(root: Path = PUBLIC_ROOT, *, split: str = "fresh-v6") -> dict[str, Any]:
    cases = score_case_by_id(root)
    gaps = gap_by_expected(root)
    rows: list[dict[str, Any]] = []
    for expected in expected_rows_for_split(root, split):
        case_id = str(expected.get("case_id"))
        expected_id = str(expected.get("finding_id"))
        case = cases.get(case_id, {})
        hmatch = match_for(case, "hypothesis_matches", expected_id)
        mmatch = match_for(case, "manual_review_matches", expected_id)
        match_type = str(hmatch.get("match_type") or "none")
        hyp_id = str(hmatch.get("generated_id") or "") if match_type != "none" else ""
        hyp = find_hypothesis(root, case_id, hyp_id) if hyp_id else None
        gap = gaps.get((case_id, expected_id), {})
        manual_id = related_manual_id(load_frozen_manual_items(root, case_id), hyp_id) or str(mmatch.get("generated_id") or "")
        rows.append({
            "case_id": case_id,
            "expected_finding_id": expected_id,
            "expected_title": expected.get("title"),
            "expected_severity": expected.get("expected_severity"),
            "expected_source_file": expected.get("source_file"),
            "expected_component": expected.get("affected_contract"),
            "expected_function": expected.get("affected_function"),
            "expected_bug_class": expected.get("bug_class"),
            "expected_impact_type": expected.get("impact_type"),
            "best_related_hypothesis_id": hyp_id,
            "best_match_type": match_type,
            "weak_match_counted_as_detection": False,
            "matched_fields": hmatch.get("matched_fields", []),
            "related_manual_review_item_id": manual_id,
            "related_component": (hyp or {}).get("contract") or expected.get("affected_contract"),
            "related_file": (hyp or {}).get("file_path") or (hyp or {}).get("file") or expected.get("source_file"),
            "related_function": (hyp or {}).get("function") or expected.get("affected_function"),
            "related_lifecycle": "; ".join(str(x) for x in (hyp or {}).get("exploit_sequence", [])[:2]) if hyp else "",
            "related_asset_flow": bool(gap.get("related_asset_flow")),
            "related_source_facts_present": bool(gap.get("related_source_fact") or hyp),
            "candidate_repairability": repairability(match_type, gap, hyp),
            "main_gap": main_gap_for(match_type, gap, hyp),
            "hypothesis_counted_as_detection": match_type in {"strict", "semantic"},
        })
    summary: dict[str, dict[str, int]] = {}
    for row in rows:
        case = summary.setdefault(row["case_id"], {"expected_findings": 0, "weak_related": 0, "strict_semantic_related": 0, "repairable": 0})
        case["expected_findings"] += 1
        case["weak_related"] += int(row["best_match_type"] == "weak")
        case["strict_semantic_related"] += int(row["best_match_type"] in {"strict", "semantic"})
        case["repairable"] += int(row["candidate_repairability"] in {"high", "medium"})
    result = {
        "status": "PASS" if rows else "BLOCKED",
        "split": split,
        "classification": "post_freeze_expected_related_inventory_not_detection",
        "expected_finding_count": len(rows),
        "weak_matches_counted_as_detections": False,
        "strict_semantic_related_count": sum(1 for r in rows if r["best_match_type"] in {"strict", "semantic"}),
        "weak_related_count": sum(1 for r in rows if r["best_match_type"] == "weak"),
        "repairable_count": sum(1 for r in rows if r["candidate_repairability"] in {"high", "medium"}),
        "case_summary": summary,
        "rows": rows,
        **base_result_flags(),
    }
    return write_json(repair_dir(root) / "expected_related_hypothesis_inventory.json", result)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Build expected-related hypothesis inventory")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="fresh-v6")
    p.add_argument("--frozen-only", action="store_true")
    args = p.parse_args(argv)
    result = build_inventory(Path(args.root), split=args.split)
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
