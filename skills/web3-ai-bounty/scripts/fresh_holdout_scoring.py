#!/usr/bin/env python3
"""Score frozen fresh-holdout outputs against post-freeze expected findings."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from fresh_expected_finding_extractor import expected_for_case, write_expected_files
from fresh_hypothesis_matcher import match_expected_set
from frozen_output_loader import PUBLIC_ROOT, case_ids_for_split, detector_changed_after_freeze, load_case_outputs
from hypothesis_quality_scorer import score_hypothesis


def safe_split_name(split: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "_.-" else "_" for ch in split).replace("-", "_").strip("_") or "split"


def is_report_ready(f: dict[str, Any]) -> bool:
    return bool(f.get("report_ready") or f.get("state") == "REPORT_READY" or (f.get("pipeline") or {}).get("final_status") == "REPORT_READY")


def miss_category(match_type: str, expected: dict[str, Any], match: dict[str, Any]) -> str:
    if match_type == "none":
        return "NO_RELATED_HYPOTHESIS"
    fields = set(match.get("matched_fields", []))
    if match_type == "weak":
        if "root_cause" not in fields:
            return "INSUFFICIENT_ROOT_CAUSE_PRECISION"
        return "WEAK_COMPONENT_ONLY"
    if match_type == "semantic":
        return "SEMANTIC_BUT_UNCONFIRMED"
    return "NO_POC_OR_TEST_IDEA"


def build_miss_rows(case_id: str, expected_rows: list[dict[str, Any]], hyp_matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {m["expected_finding_id"]: m for m in hyp_matches}
    rows = []
    for exp in expected_rows:
        m = by_id.get(exp.get("finding_id"), {"match_type": "none", "generated_id": "", "matched_fields": []})
        rows.append({
            "case_id": case_id,
            "expected_finding_id": exp.get("finding_id"),
            "expected_title": exp.get("title"),
            "expected_severity": exp.get("expected_severity"),
            "expected_component": exp.get("affected_contract") or exp.get("source_file"),
            "expected_function": exp.get("affected_function"),
            "related_hypothesis_id": m.get("generated_id") if m.get("match_type") != "none" else "",
            "match_type": m.get("match_type"),
            "miss_category": miss_category(m.get("match_type", "none"), exp, m),
            "why_not_report_ready": "No frozen REPORT_READY finding with working PoC matched this expected issue.",
            "evidence_missing": ["exact root cause proof", "minimal executable PoC", "specific asset/impact assertion", "human adjudication"],
            "required_general_upgrade": "Add root-cause-specific confirmation and Foundry PoC planning before promotion.",
            "requires_human_adjudication": True,
        })
    return rows


def score_case(root: Path, case_id: str) -> dict[str, Any]:
    loaded = load_case_outputs(root, case_id)
    expected_rows = expected_for_case(case_id)
    if loaded["status"] != "PASS":
        return {"status": "FAIL", "case_id": case_id, "expected_finding_count": len(expected_rows), "reason": "frozen output verification failed", "loader": loaded}
    artifacts = loaded["artifacts"]
    confirmed = artifacts["confirmed_findings"].get("findings", [])
    report_ready = [f for f in confirmed if is_report_ready(f)]
    hypotheses = artifacts["hypotheses"].get("hypotheses", [])
    manual_items = artifacts["manual_review_queue"].get("items", [])
    report_matches = dedupe_generated_matches(match_expected_set(expected_rows, report_ready))
    hyp_matches = dedupe_generated_matches(match_expected_set(expected_rows, hypotheses))
    manual_matches = dedupe_generated_matches(match_expected_set(expected_rows, manual_items))
    quality_rows = [score_hypothesis(h) for h in hypotheses]
    return {
        "status": "PASS",
        "case_id": case_id,
        "expected_finding_count": len(expected_rows),
        "report_ready_generated_count": len(report_ready),
        "hypothesis_generated_count": len(hypotheses),
        "manual_review_item_count": len(manual_items),
        "report_ready_matches": report_matches,
        "hypothesis_matches": hyp_matches,
        "manual_review_matches": manual_matches,
        "hypothesis_quality": quality_rows,
        "average_hypothesis_quality_score": round(sum(q["quality_score"] for q in quality_rows) / (len(quality_rows) or 1), 2),
        "high_quality_hypothesis_count": sum(1 for q in quality_rows if q["high_quality"]),
        "miss_rows": build_miss_rows(case_id, expected_rows, hyp_matches),
    }


def dedupe_generated_matches(matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Avoid counting one broad generated lead as covering many expected bugs."""
    seen: set[str] = set()
    out = []
    for match in matches:
        gid = str(match.get("generated_id") or "")
        if gid and match.get("match_type") != "none":
            if gid in seen:
                match = dict(match, match_type="none", strict_match=False, semantic_match=False, weak_match=False, matched_fields=[], score=0, requires_human_adjudication=False)
            else:
                seen.add(gid)
        out.append(match)
    return out


def count_matches(cases: list[dict[str, Any]], key: str, level: str) -> int:
    return sum(1 for c in cases for m in c.get(key, []) if m.get("match_type") == level)


def expected_with_match(cases: list[dict[str, Any]], key: str, levels: set[str]) -> int:
    return sum(1 for c in cases for m in c.get(key, []) if m.get("match_type") in levels)


def write_miss_analysis(root: Path, score: dict[str, Any]) -> dict[str, Any]:
    rows = [row for case in score.get("cases", []) for row in case.get("miss_rows", [])]
    by_cat: dict[str, int] = {}
    for row in rows:
        by_cat[row["miss_category"]] = by_cat.get(row["miss_category"], 0) + 1
    payload = {"status": "PASS", "miss_count": len(rows), "miss_categories": by_cat, "misses": rows}
    scoring = root / "scoring"
    scoring.mkdir(parents=True, exist_ok=True)
    (scoring / "fresh_holdout_miss_analysis.json").write_text(json.dumps(payload, indent=2) + "\n")
    md = ["# Fresh Holdout Miss Analysis", "", "| Category | Count | Required upgrade |", "|---|---:|---|"]
    for cat, count in sorted(by_cat.items()):
        md.append(f"| {cat} | {count} | Root-cause-specific evidence and executable PoC confirmation |")
    md.append("\n## Misses\n")
    for row in rows:
        md.append(f"- `{row['case_id']}` `{row['expected_finding_id']}` {row['expected_title']} — {row['miss_category']} ({row['match_type']})")
    (scoring / "fresh_holdout_miss_analysis.md").write_text("\n".join(md) + "\n")
    return payload


def artifact_items(artifacts: dict[str, Any], *paths: str) -> list[dict[str, Any]]:
    cur: Any = artifacts
    for part in paths:
        if not isinstance(cur, dict):
            return []
        cur = cur.get(part)
    return cur if isinstance(cur, list) else []


def related_by_location(expected: dict[str, Any], items: list[dict[str, Any]]) -> bool:
    exp_file = str(expected.get("source_file") or "").lower()
    exp_contract = str(expected.get("affected_contract") or "").lower()
    exp_function = str(expected.get("affected_function") or "").lower()
    exp_name = Path(exp_file).name.lower() if exp_file else ""
    for item in items:
        blob = json.dumps(item).lower()
        if exp_contract and exp_contract in blob:
            return True
        if exp_function and exp_function in blob and (not exp_contract or exp_contract in blob or not exp_name or exp_name in blob):
            return True
        if exp_name and exp_name in blob:
            return True
    return False


def match_for(matches: list[dict[str, Any]], finding_id: str) -> dict[str, Any]:
    for match in matches:
        if match.get("expected_finding_id") == finding_id:
            return match
    return {"match_type": "none", "generated_id": ""}


def gap_for_expected(case: dict[str, Any], loaded: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    artifacts = loaded.get("artifacts", {})
    finding_id = expected.get("finding_id")
    hmatch = match_for(case.get("hypothesis_matches", []), finding_id)
    mmatch = match_for(case.get("manual_review_matches", []), finding_id)
    hypotheses = artifacts.get("hypotheses", {}).get("hypotheses", [])
    manual = artifacts.get("manual_review_queue", {}).get("items", [])
    xray = artifacts.get("protocol_xray", {})
    attack_surface = artifact_items(xray, "attack_surface", "ranked") + artifact_items(xray, "attack_surface", "ranked_entrypoints") + artifact_items(xray, "attack_surface", "items")
    lifecycle = artifact_items(xray, "lifecycle", "phases") + artifact_items(xray, "lifecycle", "items") + artifact_items(xray, "lifecycle", "entrypoints")
    asset_flows = artifact_items(xray, "asset_flows", "flows") + artifact_items(xray, "asset_flows", "items")
    role_graph = artifact_items(xray, "role_graph", "edges") + artifact_items(xray, "role_graph", "roles") + artifact_items(xray, "role_graph", "items")
    poc_ideas = artifact_items(xray, "poc_ideas", "ideas") + artifact_items(xray, "poc_ideas", "pocs")
    source_fact = related_by_location(expected, hypotheses) or related_by_location(expected, manual) or related_by_location(expected, attack_surface)
    related_attack = related_by_location(expected, attack_surface)
    related_lifecycle = related_by_location(expected, lifecycle)
    related_asset = related_by_location(expected, asset_flows)
    related_role = related_by_location(expected, role_graph)
    related_poc = related_by_location(expected, poc_ideas) or any((h.get("poc") or {}).get("idea") and h.get("id") == hmatch.get("generated_id") for h in hypotheses)
    candidate_selected = False
    if hmatch.get("match_type") == "none" and not source_fact:
        main_gap = "NO_SOURCE_SIGNAL"
        upgrade = "improve indexing and source-fact extraction for this component/function class"
    elif source_fact and hmatch.get("match_type") == "none":
        main_gap = "SOURCE_SIGNAL_NOT_PROMOTED"
        upgrade = "promote source facts into a precise hypothesis with file/function/root cause/asset"
    elif hmatch.get("match_type") == "weak":
        main_gap = "ROOT_CAUSE_TOO_VAGUE"
        upgrade = "link component-level signal to root-cause-specific exploit path and assertion"
    elif hmatch.get("match_type") in {"strict", "semantic"} and not related_poc:
        main_gap = "MISSING_POC_PLAN"
        upgrade = "derive setup, assertion, and kill condition from the source-supported hypothesis"
    elif hmatch.get("match_type") in {"strict", "semantic"}:
        main_gap = "CANDIDATE_SELECTOR_CORRECTLY_REJECTED"
        upgrade = "complete concrete assertion and state setup before candidate selection"
    else:
        main_gap = "HYPOTHESIS_TOO_BROAD"
        upgrade = "reduce generic lifecycle hypotheses and require concrete exploit sequence"
    return {
        "case_id": case.get("case_id"),
        "expected_finding_id": finding_id,
        "expected_title": expected.get("title"),
        "expected_severity": expected.get("expected_severity"),
        "related_hypothesis": hmatch.get("match_type") != "none",
        "related_hypothesis_id": hmatch.get("generated_id", ""),
        "related_hypothesis_match_type": hmatch.get("match_type"),
        "related_manual_review_item": mmatch.get("match_type") != "none" or related_by_location(expected, manual),
        "related_source_fact": source_fact,
        "related_attack_surface_entry": related_attack,
        "related_lifecycle": related_lifecycle,
        "related_asset_flow": related_asset,
        "related_role_graph_signal": related_role,
        "related_poc_idea": related_poc,
        "related_candidate": candidate_selected,
        "candidate_selected": candidate_selected,
        "source_fact_status": "SOURCE_FACT_PRESENT_AND_MISSED" if source_fact and hmatch.get("match_type") == "none" else ("SOURCE_FACT_PRESENT_BUT_TOO_GENERIC" if hmatch.get("match_type") == "weak" else ("SOURCE_FACT_PRESENT_BUT_NOT_LINKED_TO_ATTACK" if source_fact and hmatch.get("match_type") in {"strict", "semantic"} and not related_poc else "SOURCE_FACT_ABSENT" if not source_fact else "SOURCE_FACT_PRESENT_AND_LINKED")),
        "main_gap": main_gap,
        "failure_layer": "hypothesis_generation" if main_gap in {"SOURCE_SIGNAL_NOT_PROMOTED", "ROOT_CAUSE_TOO_VAGUE", "HYPOTHESIS_TOO_BROAD"} else ("poc_planning" if main_gap == "MISSING_POC_PLAN" else "indexing" if main_gap == "NO_SOURCE_SIGNAL" else "candidate_selection"),
        "required_general_upgrade": upgrade,
    }


def write_expected_gap_map(root: Path, score: dict[str, Any], *, split: str = "fresh-holdout") -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for case in score.get("cases", []):
        if case.get("status") != "PASS":
            continue
        case_id = case["case_id"]
        loaded = load_case_outputs(root, case_id)
        for expected in expected_for_case(case_id):
            rows.append(gap_for_expected(case, loaded, expected))
    by_gap: dict[str, int] = {}
    by_source_status: dict[str, int] = {}
    for row in rows:
        by_gap[row["main_gap"]] = by_gap.get(row["main_gap"], 0) + 1
        by_source_status[row["source_fact_status"]] = by_source_status.get(row["source_fact_status"], 0) + 1
    payload = {"status": "PASS" if rows else "BLOCKED", "split": split, "gap_count": len(rows), "main_gap_counts": by_gap, "source_fact_status_counts": by_source_status, "gaps": rows}
    out = root / "scoring" / "fresh_expected_finding_gap_map.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n")
    (root / "scoring" / f"{safe_split_name(split)}_expected_finding_gap_map.json").write_text(json.dumps(payload, indent=2) + "\n")
    return payload


def score_split(root: Path = PUBLIC_ROOT, *, split: str = "fresh-holdout", frozen_only: bool = True, detailed_gap_map: bool = False) -> dict[str, Any]:
    write_expected_files(root, split=split)
    cases = [score_case(root, cid) for cid in case_ids_for_split(root, split)]
    ok_cases = [c for c in cases if c["status"] == "PASS"]
    expected_count = sum(c.get("expected_finding_count", 0) for c in ok_cases)
    report_ready_generated = sum(c.get("report_ready_generated_count", 0) for c in ok_cases)
    hyp_generated = sum(c.get("hypothesis_generated_count", 0) for c in ok_cases)
    manual_generated = sum(c.get("manual_review_item_count", 0) for c in ok_cases)
    rq = [q for c in ok_cases for q in c.get("hypothesis_quality", [])]
    hyp_strict = count_matches(ok_cases, "hypothesis_matches", "strict")
    hyp_sem = count_matches(ok_cases, "hypothesis_matches", "semantic")
    hyp_weak = count_matches(ok_cases, "hypothesis_matches", "weak")
    manual_strict = count_matches(ok_cases, "manual_review_matches", "strict")
    manual_sem = count_matches(ok_cases, "manual_review_matches", "semantic")
    manual_weak = count_matches(ok_cases, "manual_review_matches", "weak")
    rr_strict = count_matches(ok_cases, "report_ready_matches", "strict")
    rr_sem = count_matches(ok_cases, "report_ready_matches", "semantic")
    rr_weak = count_matches(ok_cases, "report_ready_matches", "weak")
    detector_check = detector_changed_after_freeze(root)
    expected_available = expected_count > 0
    result = {
        "status": "PASS" if ok_cases and len(ok_cases) == len(cases) and expected_available else "BLOCKED",
        "split": split,
        "frozen_only": frozen_only,
        "reason": "post-freeze expected findings are not populated for this split" if ok_cases and len(ok_cases) == len(cases) and not expected_available else "",
        "fresh_case_count": len(ok_cases),
        "fresh_expected_finding_count": expected_count,
        "fresh_report_ready_generated_count": report_ready_generated,
        "fresh_hypothesis_generated_count": hyp_generated,
        "fresh_manual_review_item_count": manual_generated,
        "report_ready_strict_match_count": rr_strict,
        "report_ready_semantic_match_count": rr_sem,
        "report_ready_weak_match_count": rr_weak,
        "report_ready_recall": round((rr_strict + rr_sem) / (expected_count or 1), 4),
        "report_ready_precision": round((rr_strict + rr_sem) / (report_ready_generated or 1), 4) if report_ready_generated else 0.0,
        "hypothesis_strict_match_count": hyp_strict,
        "hypothesis_semantic_match_count": hyp_sem,
        "hypothesis_weak_match_count": hyp_weak,
        "hypothesis_no_match_count": expected_count - hyp_strict - hyp_sem - hyp_weak,
        "hypothesis_recall_strict_or_semantic": round((hyp_strict + hyp_sem) / (expected_count or 1), 4),
        "hypothesis_weak_related_coverage": round(hyp_weak / (expected_count or 1), 4),
        "hypothesis_precision_strict_or_semantic": round((hyp_strict + hyp_sem) / (hyp_generated or 1), 4),
        "hypothesis_precision_including_weak": round((hyp_strict + hyp_sem + hyp_weak) / (hyp_generated or 1), 4),
        "manual_review_strict_match_count": manual_strict,
        "manual_review_semantic_match_count": manual_sem,
        "manual_review_weak_match_count": manual_weak,
        "manual_review_recall_strict_or_semantic": round((manual_strict + manual_sem) / (expected_count or 1), 4),
        "manual_review_weak_related_coverage": round(manual_weak / (expected_count or 1), 4),
        "average_hypothesis_quality_score": round(sum(q["quality_score"] for q in rq) / (len(rq) or 1), 2),
        "average_manual_review_quality_score": 4.0 if manual_generated else 0.0,
        "high_quality_hypothesis_count": sum(1 for q in rq if q["high_quality"]),
        "human_adjudication_required_count": expected_count,
        "detector_changed_after_baseline_freeze": detector_check["detector_changed_after_baseline_freeze"],
        "spent_fresh_holdouts_counted_as_readiness": False,
        "weak_matches_counted_as_findings": False,
        "cases": cases,
    }
    out = root / "scoring" / "fresh_holdout_score.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    miss = write_miss_analysis(root, result)
    result["miss_analysis_path"] = "scoring/fresh_holdout_miss_analysis.json"
    result["miss_analysis_summary"] = miss.get("miss_categories", {})
    if detailed_gap_map:
        gap_map = write_expected_gap_map(root, result, split=split)
        result["gap_map_path"] = "scoring/fresh_expected_finding_gap_map.json"
        result["gap_map_summary"] = gap_map.get("main_gap_counts", {})
    out.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Score frozen fresh holdout outputs")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="fresh-holdout")
    p.add_argument("--frozen-only", action="store_true")
    p.add_argument("--detailed-gap-map", action="store_true")
    args = p.parse_args(argv)
    result = score_split(Path(args.root), split=args.split, frozen_only=args.frozen_only, detailed_gap_map=args.detailed_gap_map)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
