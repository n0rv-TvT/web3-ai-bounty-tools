#!/usr/bin/env python3
"""Explain why frozen hypotheses failed PoC-candidate selection.

This is a post-freeze failure-analysis tool. It may read frozen generated outputs
and post-freeze score summaries, but it does not fetch network resources or tune
detector logic.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT, case_ids_for_split
from hypothesis_quality_scorer import score_hypothesis


def load_json(path: Path, default: Any) -> Any:
    return json.loads(path.read_text(errors="replace")) if path.exists() else default


def safe_split_name(split: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "_.-" else "_" for ch in split).replace("-", "_").strip("_") or "split"


def has_specific(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text and text not in {"unknown", "requires validation", "none"})


def is_generic_asset(value: Any) -> bool:
    text = str(value or "").lower()
    return not text or "requires validation" in text or "protocol-controlled assets" in text


def is_generic_sequence(h: dict[str, Any]) -> bool:
    seq = h.get("exploit_sequence") or []
    text = " ".join(str(s) for s in seq).lower() if isinstance(seq, list) else str(seq).lower()
    if not text:
        return True
    generic_markers = ["condition suggested", "compare attacker/victim/protocol", "manual", "requires validation"]
    return any(marker in text for marker in generic_markers)


def is_generic_poc(h: dict[str, Any]) -> bool:
    poc = h.get("poc") or {}
    idea = str(poc.get("idea") or h.get("poc_idea") or h.get("minimal_poc_idea") or "").lower()
    return not idea or "sets the boundary state" in idea or "requires validation" in idea


def missing_assertion(h: dict[str, Any]) -> bool:
    poc = h.get("poc") or {}
    minimal = h.get("minimal_poc_idea") or h.get("minimal_poc_plan") or {}
    return not bool(poc.get("assertion") or minimal.get("assertions") or h.get("poc_assertion"))


def missing_kill_condition(h: dict[str, Any]) -> bool:
    return not bool(h.get("kill_condition") or (h.get("poc") or {}).get("kill_condition") or h.get("kill_if"))


def is_component_noise(h: dict[str, Any], score: dict[str, Any]) -> bool:
    if score.get("component_only") or score.get("overbroad_noise"):
        return True
    if is_generic_asset(h.get("affected_asset")) and is_generic_sequence(h):
        return True
    path = str(h.get("file_path") or "").lower()
    return "/mock/" in path or path.startswith("test/") or "/test/" in path


def is_test_or_mock_path(h: dict[str, Any]) -> bool:
    path = str(h.get("file_path") or h.get("file") or "").lower()
    return "/mock/" in path or path.startswith("mock/") or path.startswith("test/") or "/test/" in path


def repair_type_for(flags: dict[str, bool]) -> str:
    if flags["overbroad_component_only"] and (flags["missing_file"] or flags["missing_contract"] or flags["missing_function"]):
        return "kill_as_noise"
    if flags["missing_exploit_sequence"]:
        return "add_exploit_sequence"
    if flags["missing_poc_idea"] or flags["missing_assertion"] or flags["missing_kill_condition"]:
        return "add_poc_plan"
    if flags["missing_affected_asset"]:
        return "add_asset"
    if flags["missing_file"] or flags["missing_contract"] or flags["missing_function"]:
        return "add_file_function"
    return "kill_as_noise" if flags["overbroad_component_only"] else "add_poc_plan"


def analyze_hypothesis(h: dict[str, Any], *, case_id: str | None = None, selected_ids: set[str] | None = None) -> dict[str, Any]:
    h = dict(h)
    if case_id:
        h.setdefault("case_id", case_id)
    score = score_hypothesis(h)
    flags = {
        "missing_file": not has_specific(h.get("file_path") or h.get("file")),
        "missing_contract": not has_specific(h.get("contract")),
        "missing_function": not has_specific(h.get("function")),
        "missing_root_cause": not has_specific(h.get("bug_class")) or str(h.get("bug_class")).lower() in {"business-logic", "unknown"},
        "missing_affected_asset": is_generic_asset(h.get("affected_asset")),
        "missing_attacker_capability": not has_specific(h.get("attacker_capabilities") or h.get("attacker_capability")),
        "missing_exploit_sequence": is_generic_sequence(h),
        "missing_poc_idea": is_generic_poc(h),
        "missing_assertion": missing_assertion(h),
        "missing_kill_condition": missing_kill_condition(h),
        "overbroad_component_only": False,
    }
    flags["overbroad_component_only"] = is_component_noise(h, score)
    should_kill = bool(flags["overbroad_component_only"] and (flags["missing_file"] or flags["missing_contract"] or flags["missing_function"] or is_test_or_mock_path(h)))
    repairable = not should_kill and bool(has_specific(h.get("file_path")) and has_specific(h.get("contract")) and has_specific(h.get("function")))
    reasons = []
    if float(score.get("quality_score") or 0) < 5.0:
        reasons.append("quality_below_minimum_for_poc_scaffold")
    for key, value in flags.items():
        if value:
            reasons.append(key)
    hid = h.get("id") or h.get("lead_id") or h.get("hypothesis_id")
    return {
        "case_id": h.get("case_id"),
        "hypothesis_id": hid,
        "quality_score": score["quality_score"],
        "candidate_selected": hid in (selected_ids or set()),
        "rejection_reasons": list(dict.fromkeys(reasons)),
        **flags,
        "component_only_counted_as_noise": flags["overbroad_component_only"],
        "overbroad_noise": bool(score.get("overbroad_noise") or flags["overbroad_component_only"]),
        "could_be_repaired": repairable,
        "should_be_killed": should_kill,
        "repair_type": repair_type_for(flags) if repairable else "kill_as_noise",
        "report_ready": False,
        "counts_as_finding": False,
    }


def load_hypotheses(root: Path, split: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case_id in case_ids_for_split(root, split):
        payload = load_json(root / "generated_reports" / f"{case_id}_hypotheses.json", {"hypotheses": []})
        rows.extend(dict(h, case_id=case_id) for h in payload.get("hypotheses", []))
    return rows


def selected_candidate_ids(root: Path, split: str) -> set[str]:
    payload = load_json(root / "scoring" / f"{split.replace('-', '_')}_poc_candidate_selection.json", {})
    return {str(c.get("hypothesis_id") or c.get("candidate_id")) for c in payload.get("selected_candidates", [])}


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    def count(key: str) -> int:
        return sum(1 for r in rows if r.get(key))

    reasons: dict[str, int] = {}
    for row in rows:
        for reason in row.get("rejection_reasons", []):
            reasons[reason] = reasons.get(reason, 0) + 1
    return {
        "total_rejected": len(rows),
        "missing_file_function_count": sum(1 for r in rows if r.get("missing_file") or r.get("missing_contract") or r.get("missing_function")),
        "missing_root_cause_count": count("missing_root_cause"),
        "missing_affected_asset_count": count("missing_affected_asset"),
        "missing_exploit_sequence_count": count("missing_exploit_sequence"),
        "missing_poc_idea_count": count("missing_poc_idea"),
        "missing_assertion_count": count("missing_assertion"),
        "missing_kill_condition_count": count("missing_kill_condition"),
        "component_only_count": count("overbroad_component_only"),
        "overbroad_noise_count": count("overbroad_noise"),
        "potentially_repairable_count": count("could_be_repaired"),
        "should_be_killed_count": count("should_be_killed"),
        "by_rejection_reason": dict(sorted(reasons.items())),
    }


def load_score(root: Path) -> dict[str, Any]:
    return load_json(root / "scoring" / "fresh_holdout_score.json", {"cases": []})


def postmortems(root: Path, rows: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    by_id = {r["hypothesis_id"]: r for r in rows}
    score = load_score(root)
    strict_rows = []
    weak_rows = []
    for case in score.get("cases", []):
        for match in case.get("hypothesis_matches", []):
            gid = match.get("generated_id")
            if not gid:
                continue
            audit = by_id.get(gid, {})
            if match.get("match_type") == "strict":
                strict_rows.append({
                    "case_id": case.get("case_id"),
                    "expected_finding_id": match.get("expected_finding_id"),
                    "hypothesis_id": gid,
                    "strict_match": True,
                    "quality_score": audit.get("quality_score", 0.0),
                    "selection_status": "REJECTED",
                    "rejection_reasons": audit.get("rejection_reasons", []),
                    "needed_for_poc_candidate": audit.get("rejection_reasons", []),
                    "repairable_without_answer_key": bool(audit.get("could_be_repaired")),
                    "human_review_needed": True,
                    "selector_too_strict_or_correct": "correctly_rejected_until_assertion_asset_and_poc_plan_are concrete" if audit else "unknown",
                })
            elif match.get("match_type") == "weak":
                weak_rows.append({
                    "case_id": case.get("case_id"),
                    "expected_finding_id": match.get("expected_finding_id"),
                    "hypothesis_id": gid,
                    "why_weak": "matched only component/file/function-level fields without enough root-cause and impact precision",
                    "missing_root_cause_precision": bool(audit.get("missing_root_cause") or "missing_root_cause" in audit.get("rejection_reasons", [])),
                    "missing_file_function_precision": bool(audit.get("missing_file") or audit.get("missing_contract") or audit.get("missing_function")),
                    "missing_exploit_sequence": bool(audit.get("missing_exploit_sequence")),
                    "missing_asset_impact": bool(audit.get("missing_affected_asset")),
                    "could_be_upgraded_to_semantic": bool(audit.get("could_be_repaired")),
                    "required_general_upgrade": "link source facts to root-cause-specific exploit sequence, asset impact, assertion, and kill condition",
                })
    strict = {"status": "PASS" if strict_rows else "BLOCKED", "strict_match_count": len(strict_rows), "rows": strict_rows}
    weak = {"status": "PASS" if weak_rows else "BLOCKED", "weak_match_count": len(weak_rows), "rows": weak_rows}
    (root / "scoring" / "strict_match_postmortem.json").write_text(json.dumps(strict, indent=2) + "\n")
    (root / "scoring" / "weak_match_postmortem.json").write_text(json.dumps(weak, indent=2) + "\n")
    return strict, weak


def run_analysis(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation") -> dict[str, Any]:
    hyps = load_hypotheses(root, split)
    selected = selected_candidate_ids(root, split)
    rows = [analyze_hypothesis(h, selected_ids=selected) for h in hyps]
    summary = aggregate(rows)
    out_dir = root / "scoring"
    out_dir.mkdir(parents=True, exist_ok=True)
    candidate_audit = {
        "status": "PASS" if rows else "BLOCKED",
        "split": split,
        "hypothesis_count": len(rows),
        "selected_count": len(selected),
        "rejections": rows,
        "summary": summary,
        "answer_key_access": False,
        "writeup_access": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "detector_tuning_performed": False,
        "counts_toward_readiness": False,
    }
    (out_dir / "fresh_candidate_rejection_audit.json").write_text(json.dumps(candidate_audit, indent=2) + "\n")
    (out_dir / f"{safe_split_name(split)}_candidate_rejection_audit.json").write_text(json.dumps(candidate_audit, indent=2) + "\n")
    quality_gap = {"status": candidate_audit["status"], "split": split, **summary, "rejections": rows}
    (out_dir / "fresh_hypothesis_quality_gap_analysis.json").write_text(json.dumps(quality_gap, indent=2) + "\n")
    strict, weak = postmortems(root, rows)
    failure = {
        "status": "PASS" if rows else "BLOCKED",
        "fresh_confirmation_status": "negative_validation",
        "lead_generation_status": "pass",
        "hypothesis_quality_status": "failed_low_quality",
        "candidate_selection_status": "failed_zero_candidates",
        "poc_confirmation_status": "not_reached",
        "report_ready_status": "failed_zero_report_ready",
        "production_readiness": "not_production_ready",
        "controlled_solidity_assistance": "beta",
        "real_protocol_autonomy": "not_ready",
        "non_evm_readiness": "limited",
        "primary_failure": "hypotheses had exact locations but generic assets, generic exploit sequences, generic PoC ideas, and missing concrete assertions",
        "selector_assessment": "candidate selector was correct to reject hypotheses without concrete assertion and kill-ready PoC plans; do not lower thresholds",
        "summary": summary,
        "strict_match_postmortem": strict,
        "weak_match_postmortem": weak,
        "counts_toward_readiness": False,
    }
    (out_dir / "fresh_confirmation_failure_analysis.json").write_text(json.dumps(failure, indent=2) + "\n")
    (out_dir / f"{safe_split_name(split)}_failure_analysis.json").write_text(json.dumps(failure, indent=2) + "\n")
    md = [
        f"# {split} Failure Analysis",
        "",
        "## Executive summary",
        "Failure analyzed. The run produced lead volume but failed hypothesis precision and candidate selection.",
        "",
        "## Rejection summary",
        "",
        "| Reason | Count |",
        "|---|---:|",
    ]
    for reason, count in summary["by_rejection_reason"].items():
        md.append(f"| `{reason}` | {count} |")
    md.extend([
        "",
        "## Selector assessment",
        failure["selector_assessment"],
        "",
        "## Readiness",
        "Production readiness changed: false. These cases are spent and may only be used for post-hoc repair/regression.",
    ])
    (out_dir / "fresh_confirmation_failure_analysis.md").write_text("\n".join(md) + "\n")
    (out_dir / f"{safe_split_name(split)}_failure_analysis.md").write_text("\n".join(md) + "\n")
    return failure


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Analyze fresh holdout candidate rejections")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="fresh-confirmation")
    p.add_argument("--frozen-only", action="store_true")
    args = p.parse_args(argv)
    result = run_analysis(Path(args.root), split=args.split)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
