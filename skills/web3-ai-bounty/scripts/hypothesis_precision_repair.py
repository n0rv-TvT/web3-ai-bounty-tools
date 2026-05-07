#!/usr/bin/env python3
"""Post-hoc precision repair for frozen hypothesis artifacts.

This script is failure-analysis/regression support only. It consumes frozen
detector outputs, enriches hypotheses with generic PoC-readiness fields where
source facts support that, and records exactly why the repaired rows still do
not count as findings or readiness evidence.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from candidate_rejection_analyzer import analyze_hypothesis
from frozen_output_loader import PUBLIC_ROOT, case_ids_for_split, load_case_outputs
from poc_readiness_enricher import enrich_hypothesis


def safe_id(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "_.-" else "_" for ch in value).strip("_") or "split"


def load_frozen_hypotheses(root: Path, split: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    hypotheses: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    for case_id in case_ids_for_split(root, split):
        loaded = load_case_outputs(root, case_id)
        if loaded.get("status") != "PASS":
            cases.append({"case_id": case_id, "status": "FAIL", "reason": "frozen output verification failed"})
            continue
        rows = loaded["artifacts"]["hypotheses"].get("hypotheses", [])
        hypotheses.extend(dict(h, case_id=case_id) for h in rows)
        cases.append({"case_id": case_id, "status": "PASS", "hypothesis_count": len(rows)})
    return hypotheses, cases


def repair_row(h: dict[str, Any]) -> dict[str, Any]:
    audit = analyze_hypothesis(h)
    enriched = enrich_hypothesis(h)
    repaired = enriched.get("repaired_hypothesis", {})
    status = "KILLED_AS_NOISE" if audit.get("should_be_killed") else enriched.get("status")
    is_repaired = bool(enriched.get("repair_actions"))
    poc_ready = bool(enriched.get("poc_ready")) and not audit.get("should_be_killed")
    high_quality = bool(enriched.get("high_quality")) and not audit.get("should_be_killed")
    return {
        "case_id": h.get("case_id"),
        "hypothesis_id": h.get("id") or h.get("lead_id") or h.get("hypothesis_id"),
        "repair_status": status,
        "pre_repair_audit": audit,
        "should_be_killed": bool(audit.get("should_be_killed")),
        "was_repaired": is_repaired,
        "original_quality_score": enriched.get("original_quality_score"),
        "repaired_quality_score": enriched.get("repaired_quality_score"),
        "quality_delta": enriched.get("quality_delta", 0.0),
        "repair_actions": enriched.get("repair_actions", []),
        "state_setup": enriched.get("state_setup", {}),
        "assertion_plan": enriched.get("assertion_plan", {}),
        "repaired_hypothesis": repaired,
        "poc_ready_after_repair": poc_ready,
        "high_quality_after_repair": high_quality,
        "manual_completion_required": True,
        "report_ready": False,
        "counts_as_finding": False,
        "counts_toward_readiness": False,
    }


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_status: dict[str, int] = {}
    by_action: dict[str, int] = {}
    for row in rows:
        by_status[str(row.get("repair_status"))] = by_status.get(str(row.get("repair_status")), 0) + 1
        for action in row.get("repair_actions", []):
            by_action[str(action)] = by_action.get(str(action), 0) + 1
    return {
        "total_hypotheses": len(rows),
        "repaired_count": sum(1 for r in rows if r.get("was_repaired")),
        "killed_as_noise_count": sum(1 for r in rows if r.get("should_be_killed")),
        "blocked_missing_location_count": sum(1 for r in rows if r.get("repair_status") == "BLOCKED_MISSING_LOCATION"),
        "poc_ready_after_repair_count": sum(1 for r in rows if r.get("poc_ready_after_repair")),
        "high_quality_after_repair_count": sum(1 for r in rows if r.get("high_quality_after_repair")),
        "report_ready_created_count": 0,
        "counts_toward_readiness_count": 0,
        "by_repair_status": dict(sorted(by_status.items())),
        "by_repair_action": dict(sorted(by_action.items())),
    }


def top_repairable(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    repairable = [r for r in rows if r.get("was_repaired") and not r.get("should_be_killed")]
    repairable.sort(key=lambda r: (float(r.get("repaired_quality_score") or 0.0), float(r.get("quality_delta") or 0.0)), reverse=True)
    out: list[dict[str, Any]] = []
    for rank, row in enumerate(repairable[:limit], start=1):
        h = row.get("repaired_hypothesis", {})
        out.append({
            "rank": rank,
            "case_id": row.get("case_id"),
            "hypothesis_id": row.get("hypothesis_id"),
            "file_path": h.get("file_path") or h.get("file"),
            "contract": h.get("contract"),
            "function": h.get("function"),
            "bug_class": h.get("bug_class"),
            "affected_asset": h.get("affected_asset"),
            "repaired_quality_score": row.get("repaired_quality_score"),
            "repair_actions": row.get("repair_actions", []),
            "next_step": "manual source trace, then implement/kill the local PoC plan; do not count this spent holdout toward readiness",
            "posthoc_only": True,
            "counts_toward_readiness": False,
        })
    return out


def run_split(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation", top: int = 10) -> dict[str, Any]:
    hypotheses, cases = load_frozen_hypotheses(root, split)
    rows = [repair_row(h) for h in hypotheses]
    by_case: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_case.setdefault(str(row.get("case_id")), []).append(row)
    out_dir = root / "scoring" / "precision_repair"
    out_dir.mkdir(parents=True, exist_ok=True)
    for case_id, case_rows in by_case.items():
        (out_dir / f"{case_id}_precision_repair.json").write_text(json.dumps({"case_id": case_id, "repairs": case_rows}, indent=2) + "\n")
    summary = summarize(rows)
    result = {
        "status": "PASS" if rows and all(c.get("status") == "PASS" for c in cases) else "BLOCKED",
        "split": split,
        "classification": "post_hoc_failure_analysis_only",
        "cases": cases,
        "summary": summary,
        "top_repairable": top_repairable(rows, top),
        "repairs": rows,
        "answer_key_access": False,
        "writeup_access": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "detector_tuning_performed": False,
        "thresholds_weakened": False,
        "report_ready_created": False,
        "counts_as_finding": False,
        "production_readiness_changed": False,
        "counts_toward_readiness": False,
    }
    scoring = root / "scoring"
    scoring.mkdir(parents=True, exist_ok=True)
    (scoring / f"{safe_id(split)}_hypothesis_precision_repair.json").write_text(json.dumps(result, indent=2) + "\n")
    if split == "fresh-confirmation":
        (scoring / "fresh_hypothesis_precision_repair.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Repair frozen hypotheses for post-hoc precision analysis")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="fresh-confirmation")
    p.add_argument("--frozen-only", action="store_true")
    p.add_argument("--top", type=int, default=10)
    args = p.parse_args(argv)
    result = run_split(Path(args.root), split=args.split, top=args.top)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
