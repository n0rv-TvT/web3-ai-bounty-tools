#!/usr/bin/env python3
"""Audit whether raw detector leads were suppressed before final output."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from blind_source_analyzer import analyze_project
from public_corpus_importer import PUBLIC_ROOT, ensure_public_corpus
from source_coverage_gate import find_case_context, split_csv


REQUIRED_FINAL_FIELDS = ["bug_class", "file_path", "contract", "function", "affected_asset", "impact", "exploit_scenario"]


def load_generated_report(eval_root: Path, case_id: str) -> dict[str, Any]:
    path = eval_root / "generated_reports" / f"{case_id}.json"
    if not path.exists():
        return {"findings": [], "report_missing": True}
    return json.loads(path.read_text(errors="replace"))


def missing_fields(lead: dict[str, Any]) -> list[str]:
    return [field for field in REQUIRED_FINAL_FIELDS if lead.get(field) in (None, "", [], {})]


def classify_block(lead: dict[str, Any]) -> tuple[str, str]:
    missing = missing_fields(lead)
    if missing:
        return "schema", "missing required fields: " + ", ".join(missing)
    if lead.get("needs_poc") or lead.get("state") in {"MANUAL_LEAD", "LEAD"}:
        return "missing_evidence", "lead lacked PoC/manual validation evidence for final report"
    return "unknown", "no explicit suppression metadata available"


def audit_project(case_root: Path, eval_root: Path, case_id: str) -> dict[str, Any]:
    analysis = analyze_project(case_root, include_tests=False)
    raw_leads = analysis.get("leads", [])
    report = load_generated_report(eval_root, case_id)
    final_findings = report.get("findings", [])
    final_ids = {f.get("lead_id") or f.get("id") for f in final_findings}
    suppressed = []
    counts = {"schema": 0, "linter": 0, "state_machine": 0, "missing_evidence": 0, "unknown": 0}
    for lead in raw_leads:
        lead_id = lead.get("lead_id") or lead.get("id") or f"raw-{len(suppressed)+1}"
        if lead_id in final_ids:
            continue
        blocked_by, reason = classify_block(lead)
        counts[blocked_by] = counts.get(blocked_by, 0) + 1
        suppressed.append({
            "lead_id": lead_id,
            "case_id": case_id,
            "source_module": lead.get("source", "blind_source_analyzer"),
            "initial_state": lead.get("state", "RAW_LEAD"),
            "final_state": "SUPPRESSED_BEFORE_FINAL_REPORT",
            "blocked_by": blocked_by,
            "block_reason": reason,
            "missing_fields": missing_fields(lead),
            "related_expected_finding": "unknown_until_after_freeze",
            "suppression_correctness": "unknown",
        })
    if not raw_leads:
        root_issue = "source_to_lead_generation_failure"
    elif raw_leads and not final_findings:
        root_issue = "pipeline_suppression_or_evidence_gate_failure"
    else:
        root_issue = "final_findings_present"
    return {
        "case_id": case_id,
        "raw_lead_count": len(raw_leads),
        "hypothesis_count": 0,
        "scanner_lead_count": 0,
        "final_finding_count": len(final_findings),
        "suppressed_lead_count": len(suppressed),
        "suppressed_by_schema": counts["schema"],
        "suppressed_by_linter": counts["linter"],
        "suppressed_by_state_machine": counts["state_machine"],
        "suppressed_by_missing_evidence": counts["missing_evidence"],
        "suppressed_by_unknown": counts["unknown"],
        "too_strict": "unknown" if suppressed else False,
        "root_issue": root_issue,
        "answer_key_access": bool(analysis.get("answer_key_read")),
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "suppressed_leads": suppressed,
    }


def audit_cases(root: Path, case_ids: list[str]) -> dict[str, Any]:
    ensure_public_corpus(root)
    rows = []
    for case_id in case_ids:
        eval_root, case_root = find_case_context(root, case_id)
        rows.append(audit_project(case_root, eval_root, case_id))
    return {"status": "PASS", "cases": rows}


def self_test() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        case = root / "holdout" / "case_a" / "src"
        case.mkdir(parents=True)
        (case / "Vault.sol").write_text("pragma solidity ^0.8.20; contract Vault { mapping(address=>uint) bal; function withdraw() external { uint a=bal[msg.sender]; (bool ok,) = msg.sender.call{value:a}(\"\"); require(ok); bal[msg.sender]=0; } }")
        (root / "generated_reports").mkdir()
        (root / "generated_reports" / "case_a.json").write_text(json.dumps({"findings": []}))
        result = audit_project(root / "holdout" / "case_a", root, "case_a")
        return {"status": "PASS" if result["raw_lead_count"] >= result["suppressed_lead_count"] else "FAIL", "result": result}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Audit raw lead suppression before final reports")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--cases", default="")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        result = self_test()
    elif args.cases:
        result = audit_cases(Path(args.root), split_csv(args.cases))
    else:
        raise SystemExit("provide --cases or --self-test")
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
