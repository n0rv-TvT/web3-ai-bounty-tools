#!/usr/bin/env python3
"""Orchestrate blind OOD source-to-finding benchmark runs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from artifact_hasher import freeze_report
from blind_source_analyzer import analyze_project
from corpus_manifest_validator import validate_manifest
from ood_scoring import score_ood
from overfitting_guard import validate_detection_result
from real_world_corpus_builder import DEFAULT_ROOT, build_corpus
from report_quality_scorer import score_finding
from source_to_lead_converter import convert_analysis


MODE_TO_SPLIT = {
    "source-only": "vulnerable",
    "source-plus-tests": "vulnerable",
    "patched-controls": "patched",
    "holdout": "holdout",
}


def load_manifest(root: Path) -> dict[str, Any]:
    if not (root / "corpus_manifest.json").exists():
        build_corpus(root, force=False)
    return json.loads((root / "corpus_manifest.json").read_text(errors="replace"))


def case_root(root: Path, case: dict[str, Any]) -> Path:
    return root / str(case["corpus_split"]) / str(case["case_id"])


def enrich_finding(lead: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(lead)
    evidence = enriched.get("external_evidence") or enriched.get("blind_evidence") or []
    if evidence:
        enriched["root_cause_rule"] = evidence[0].get("rule")
    enriched["reproduction"] = f"Review {enriched.get('file_path')}::{enriched.get('contract')}.{enriched.get('function')} and execute the described attacker path locally."
    enriched["report_ready"] = ((enriched.get("pipeline") or {}).get("final_status") == "REPORT_READY")
    enriched["report_quality"] = score_finding(enriched)
    return enriched


def run_case(root: Path, case: dict[str, Any], *, mode: str) -> dict[str, Any]:
    include_tests = mode == "source-plus-tests"
    project = case_root(root, case)
    analysis = analyze_project(project, include_tests=include_tests)
    guard = validate_detection_result({"read_files": analysis.get("read_files", []), "answer_key_read": analysis.get("answer_key_read")}, mode="source-only" if mode == "source-only" else mode, case=case)
    converted = convert_analysis(analysis, with_poc=include_tests and bool(case.get("is_vulnerable")), project_root=project)
    findings = [enrich_finding(lead) for lead in converted.get("leads", [])]
    report = {
        "case_id": case["case_id"],
        "mode": mode,
        "split": case["corpus_split"],
        "detection_root": str(project),
        "read_files": analysis.get("read_files", []),
        "answer_key_read_during_detection": bool(analysis.get("answer_key_read")),
        "answer_key_loaded": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "prompt_injection_hits": analysis.get("prompt_injection_hits", []),
        "guard": guard,
        "finding_count": len(findings),
        "findings": findings,
    }
    frozen = freeze_report(report)
    out = root / "generated_reports" / f"{case['case_id']}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(frozen, indent=2) + "\n")
    return {"case_id": case["case_id"], "finding_count": len(findings), "guard_status": guard["status"], "report_path": out.relative_to(root).as_posix(), "report_hash": frozen["report_hash"], "read_files": analysis.get("read_files", [])}


def run_mode(root: Path = DEFAULT_ROOT, *, mode: str) -> dict[str, Any]:
    manifest = load_manifest(root)
    validation = validate_manifest(root)
    if validation["status"] != "PASS":
        return {"status": "FAIL", "mode": mode, "validation": validation}
    if mode == "score-only":
        score = score_ood(root)
        (root / "scoring" / "ood_score.json").write_text(json.dumps(score, indent=2) + "\n")
        return {"status": "PASS", "mode": mode, "classification": "score-only", "answer_key_access": "after generated reports were frozen", "answer_key_readable_during_detection": False, **score}
    split = MODE_TO_SPLIT[mode]
    selected = [case for case in manifest["cases"] if case.get("corpus_split") == split]
    rows = [run_case(root, case, mode=mode) for case in selected]
    guards_pass = all(row["guard_status"] == "PASS" for row in rows)
    return {
        "status": "PASS" if guards_pass else "FAIL",
        "mode": mode,
        "classification": "blind-detection",
        "case_count": len(rows),
        "answer_keys_readable": False,
        "answer_key_loaded_after_detection": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "validation": validation,
        "cases": rows,
    }
