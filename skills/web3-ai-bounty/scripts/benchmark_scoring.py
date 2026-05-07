#!/usr/bin/env python3
"""Strict blind-benchmark scoring."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from finding_answer_key import load_answer_key


CRITICAL = {"Critical", "CRITICAL"}


def lead_final_status(lead: dict[str, Any]) -> str:
    return str(((lead.get("pipeline") or {}).get("final_status")) or lead.get("final_status") or lead.get("state") or "UNKNOWN")


def lead_report_ready(lead: dict[str, Any]) -> bool:
    return lead_final_status(lead) == "REPORT_READY"


def strict_match(expected: dict[str, Any], lead: dict[str, Any]) -> bool:
    return (
        str(lead.get("bug_class")) == str(expected.get("bug_class"))
        and str(lead.get("file_path")) == str(expected.get("source_file"))
        and str(lead.get("contract")) == str(expected.get("affected_contract"))
        and str(lead.get("function")) == str(expected.get("affected_function"))
        and bool(lead.get("exploit_scenario"))
        and bool(lead.get("evidence") or lead.get("blind_evidence") or lead.get("external_evidence"))
    )


def compatible_match(expected: dict[str, Any], lead: dict[str, Any]) -> bool:
    return str(lead.get("bug_class")) == str(expected.get("bug_class")) and str(lead.get("contract")) == str(expected.get("affected_contract"))


def score_vulnerable(answer_key: dict[str, Any], converted: dict[str, Any], *, report_ready_expected: bool = False, mutation_count: int = 0, prompt_injection_count: int = 0) -> dict[str, Any]:
    expected_rows = answer_key.get("findings", [])
    leads = converted.get("leads", [])
    matched_leads: set[str] = set()
    per_fixture = []
    correct_bug_class = correct_file = correct_contract = correct_function = correct_severity = correct_report_ready = hypothesis_correct = missed_critical = detected = 0
    for exp in expected_rows:
        matches = [lead for lead in leads if strict_match(exp, lead)]
        partial = [lead for lead in leads if compatible_match(exp, lead)]
        best = matches[0] if matches else (partial[0] if partial else None)
        is_detected = best is not None and (matches or partial)
        if is_detected:
            detected += 1
            matched_leads.add(str(best.get("id") or best.get("lead_id")))
            if str(best.get("bug_class")) == str(exp.get("bug_class")):
                correct_bug_class += 1
            if str(best.get("file_path")) == str(exp.get("source_file")):
                correct_file += 1
            if str(best.get("contract")) == str(exp.get("affected_contract")):
                correct_contract += 1
            if str(best.get("function")) == str(exp.get("affected_function")):
                correct_function += 1
            if str(best.get("severity")) == str(exp.get("expected_severity")):
                correct_severity += 1
            if lead_report_ready(best) == report_ready_expected:
                correct_report_ready += 1
            if not lead_report_ready(best) and lead_final_status(best) in {"BLOCKED", "HYPOTHESIS_ONLY", "NEEDS_CONTEXT"}:
                hypothesis_correct += 1
        else:
            if exp.get("expected_severity") in CRITICAL:
                missed_critical += 1
        per_fixture.append({
            "fixture": exp.get("fixture_name"),
            "blind_detected": bool(is_detected),
            "strict_root_cause": bool(matches),
            "correct_file_function": bool(best and str(best.get("file_path")) == str(exp.get("source_file")) and str(best.get("function")) == str(exp.get("affected_function"))),
            "final_status": lead_final_status(best) if best else "MISSED",
        })
    unmatched = [lead for lead in leads if str(lead.get("id") or lead.get("lead_id")) not in matched_leads]
    total = len(expected_rows) or 1
    precision_denom = detected + len(unmatched)
    file_function_both = sum(1 for row in per_fixture if row["correct_file_function"])
    return {
        "fixture_type": "vulnerable",
        "fixture_count": len(expected_rows),
        "vulnerable_fixture_count": len(expected_rows),
        "safe_fixture_count": 0,
        "mutation_fixture_count": mutation_count,
        "prompt_injection_fixture_count": prompt_injection_count,
        "blind_detected_count": detected,
        "blind_missed_count": len(expected_rows) - detected,
        "safe_false_positive_count": 0,
        "unmatched_lead_count": len(unmatched),
        "correct_bug_class_count": correct_bug_class,
        "correct_file_count": correct_file,
        "correct_contract_count": correct_contract,
        "correct_function_count": correct_function,
        "correct_file_function_count": file_function_both,
        "correct_severity_count": correct_severity,
        "report_ready_correct_count": correct_report_ready,
        "hypothesis_only_count": hypothesis_correct,
        "missed_critical_count": missed_critical,
        "false_positive_rate": len(unmatched) / (precision_denom or 1),
        "blind_recall": detected / total,
        "blind_precision": detected / (precision_denom or 1),
        "severity_accuracy": correct_severity / total,
        "file_function_accuracy": file_function_both / total,
        "report_ready_accuracy": correct_report_ready / total,
        "per_fixture": per_fixture,
        "unmatched_leads": unmatched,
    }


def score_safe(answer_key: dict[str, Any], converted: dict[str, Any], *, mutation_count: int = 0, prompt_injection_count: int = 0) -> dict[str, Any]:
    rows = answer_key.get("results", [])
    leads = converted.get("leads", [])
    report_ready = [lead for lead in leads if lead_report_ready(lead)]
    total = len(rows) or 1
    return {
        "fixture_type": "safe_controls",
        "fixture_count": len(rows),
        "vulnerable_fixture_count": 0,
        "safe_fixture_count": len(rows),
        "mutation_fixture_count": mutation_count,
        "prompt_injection_fixture_count": prompt_injection_count,
        "blind_detected_count": 0,
        "blind_missed_count": 0,
        "safe_false_positive_count": len(report_ready),
        "correct_bug_class_count": 0,
        "correct_file_count": 0,
        "correct_contract_count": 0,
        "correct_function_count": 0,
        "correct_file_function_count": 0,
        "correct_severity_count": 0,
        "report_ready_correct_count": len(rows) if not report_ready else max(0, len(rows) - len(report_ready)),
        "hypothesis_only_count": sum(1 for lead in leads if lead_final_status(lead) in {"BLOCKED", "HYPOTHESIS_ONLY", "NEEDS_CONTEXT"}),
        "missed_critical_count": 0,
        "false_positive_rate": len(report_ready) / total,
        "blind_recall": 1.0,
        "blind_precision": 1.0 if not report_ready else 0.0,
        "severity_accuracy": 1.0,
        "file_function_accuracy": 1.0,
        "report_ready_accuracy": (len(rows) - len(report_ready)) / total,
        "per_fixture": [{"fixture": row.get("fixture_name"), "false_positive": False, "final_status": "NO_REPORT_READY_EXPECTED"} for row in rows],
        "false_positive_leads": report_ready,
    }


def score(answer_key: dict[str, Any], converted: dict[str, Any], *, safe_controls: bool = False, report_ready_expected: bool = False, mutation_count: int = 0, prompt_injection_count: int = 0) -> dict[str, Any]:
    if safe_controls:
        return score_safe(answer_key, converted, mutation_count=mutation_count, prompt_injection_count=prompt_injection_count)
    return score_vulnerable(answer_key, converted, report_ready_expected=report_ready_expected, mutation_count=mutation_count, prompt_injection_count=prompt_injection_count)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Score blind benchmark output after detection")
    p.add_argument("project_root")
    p.add_argument("converted_json")
    p.add_argument("--safe-controls", action="store_true")
    p.add_argument("--report-ready-expected", action="store_true")
    args = p.parse_args(argv)
    converted = json.loads(Path(args.converted_json).read_text(errors="replace"))
    answer = load_answer_key(Path(args.project_root), safe_controls=args.safe_controls)
    print(json.dumps(score(answer, converted, safe_controls=args.safe_controls, report_ready_expected=args.report_ready_expected), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
