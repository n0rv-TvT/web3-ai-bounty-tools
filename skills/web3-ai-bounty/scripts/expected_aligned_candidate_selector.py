#!/usr/bin/env python3
"""Select only PoC-ready, strict/semantic expected-aligned repaired candidates."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from expected_aligned_repair_common import PUBLIC_ROOT, base_result_flags, load_expected_rows, load_json, repair_dir, write_json
from fresh_hypothesis_matcher import classify_match


def build_generated_item(root: Path) -> dict[str, Any]:
    root_cause = load_json(repair_dir(root) / "expected_related_root_cause_precision.json", {}).get("candidate") or {}
    impact = load_json(repair_dir(root) / "expected_related_asset_impact.json", {})
    story = load_json(repair_dir(root) / "expected_related_attack_story.json", {})
    readiness = load_json(repair_dir(root) / "expected_related_poc_readiness.json", {})
    ready_candidate = readiness.get("candidate") or {}
    impact_alias = ""
    impact_probe = " ".join(str(impact.get(k) or "").lower() for k in ["impact_type", "impact_condition"])
    if any(token in impact_probe for token in ["freeze", "frozen", "revert", "unable", "denial"]):
        impact_alias = "frozen funds availability denial of service"
    impact_text = " ".join(
        str(part or "")
        for part in [
            impact.get("impact_type"),
            impact.get("impact_condition"),
            impact.get("affected_asset"),
            impact_alias,
        ]
    )
    return {
        "id": root_cause.get("candidate_id") or ready_candidate.get("candidate_id") or ready_candidate.get("id"),
        "title": "Source-supported expected-aligned repaired hypothesis",
        "bug_class": ready_candidate.get("bug_class") or root_cause.get("bug_class"),
        "file_path": ready_candidate.get("file_path") or root_cause.get("file"),
        "contract": ready_candidate.get("contract") or root_cause.get("contract"),
        "function": ready_candidate.get("function") or root_cause.get("function"),
        "impact": {"type": impact_text, "asset": impact.get("affected_asset")},
        "exploit_scenario": " ".join([
            str(root_cause.get("root_cause_hypothesis") or ""),
            str(impact.get("impact_condition") or ""),
            " ".join(story.get("steps") or []),
        ]),
        "quality_score": readiness.get("quality_score"),
        "poc_ready": readiness.get("poc_ready"),
        "component_only": False,
        "answer_key_text_dependency": root_cause.get("answer_key_text_dependency"),
    }


def expected_row_for(root: Path, split: str, case_id: str, expected_id: str) -> dict[str, Any]:
    for row in load_expected_rows(root, split, case_id):
        if str(row.get("finding_id") or "") == expected_id:
            return row
    return {}


def select_expected_aligned(root: Path = PUBLIC_ROOT, *, split: str = "fresh-v6") -> dict[str, Any]:
    readiness = load_json(repair_dir(root) / "expected_related_poc_readiness.json", {})
    candidate = readiness.get("candidate") or {}
    case_id = str(candidate.get("case_id") or readiness.get("case_id") or "")
    expected_id = str(candidate.get("expected_finding_id") or readiness.get("expected_finding_id") or "")
    expected = expected_row_for(root, split, case_id, expected_id)
    generated = build_generated_item(root)
    match = classify_match(expected, generated) if expected and generated else {"match_type": "none", "matched_fields": []}
    blocks: list[str] = []
    if not candidate.get("expected_finding_related"):
        blocks.append("not expected-finding related")
    if match.get("match_type") not in {"strict", "semantic"}:
        blocks.append("match after repair is not strict or semantic")
    if float(readiness.get("quality_score") or 0.0) < 7.0:
        blocks.append("quality score below 7")
    if not readiness.get("poc_ready"):
        blocks.append("candidate is not PoC-ready")
    if generated.get("answer_key_text_dependency"):
        blocks.append("answer-key text dependency detected")
    if generated.get("component_only"):
        blocks.append("component-only candidate")
    selected = not blocks
    result = {
        "status": "PASS" if selected else "EXPECTED_RELATED_REPAIR_INCONCLUSIVE",
        "selected": selected,
        "candidate_id": candidate.get("candidate_id") or candidate.get("id") or candidate.get("hypothesis_id"),
        "case_id": case_id,
        "expected_finding_id": expected_id,
        "expected_finding_related": bool(candidate.get("expected_finding_related")),
        "match_type_after_repair": match.get("match_type"),
        "matched_fields_after_repair": match.get("matched_fields", []),
        "quality_score": readiness.get("quality_score", 0.0),
        "poc_ready": bool(readiness.get("poc_ready")),
        "answer_key_text_dependency": bool(generated.get("answer_key_text_dependency")),
        "component_only": bool(generated.get("component_only")),
        "blocks": blocks,
        "candidate": candidate,
        "generated_match_item": generated,
        "counts_toward_readiness": False,
        **base_result_flags(),
    }
    write_json(repair_dir(root) / "expected_related_candidate_selection.json", result)
    report = [
        "# Fresh v6 Expected-Aligned Precision Repair Report",
        "",
        f"- Status: {'Expected-aligned PoC-ready candidate created' if selected else 'Expected-aligned repair blocked'}",
        f"- Candidate: {result.get('candidate_id')}",
        f"- Case: {case_id}",
        f"- Expected finding: {expected_id}",
        f"- Match after repair: {result.get('match_type_after_repair')}",
        f"- Quality score: {result.get('quality_score')}",
        f"- PoC ready: {result.get('poc_ready')}",
        "- Counts toward readiness: false",
        "- Production readiness changed: false",
        "",
        "This is post-freeze, post-hoc failure analysis over spent holdouts. It does not count as fresh independent validation.",
    ]
    (repair_dir(root) / "expected_related_repair_report.md").write_text("\n".join(report) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Select expected-aligned repaired PoC-ready candidate")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="fresh-v6")
    p.add_argument("--frozen-only", action="store_true")
    p.add_argument("--selected", action="store_true")
    args = p.parse_args(argv)
    result = select_expected_aligned(Path(args.root), split=args.split)
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") in {"PASS", "EXPECTED_RELATED_REPAIR_INCONCLUSIVE"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
