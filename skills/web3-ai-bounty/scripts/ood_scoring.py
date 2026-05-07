#!/usr/bin/env python3
"""Score frozen OOD benchmark generated reports against hidden answer keys."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from finding_matcher import match_case
from overfitting_guard import validate_frozen_before_scoring
from report_quality_scorer import score_finding


CRITICAL = {"Critical", "CRITICAL"}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace"))


def is_report_ready(finding: dict[str, Any]) -> bool:
    pipeline = finding.get("pipeline") or {}
    return bool(finding.get("report_ready") or pipeline.get("final_status") == "REPORT_READY" or finding.get("state") == "REPORT_READY")


def score_split(cases: list[dict[str, Any]], root: Path, *, split_name: str) -> dict[str, Any]:
    detected = missed = matched_strict = correct_severity = correct_file_fn = report_ready_correct = missed_critical = false_positive = 0
    root_cause_correct = 0
    total_quality = 0.0
    quality_count = 0
    per_case: list[dict[str, Any]] = []
    all_findings = 0
    true_positive_findings = 0
    for case in cases:
        expected = load_json(root / case["answer_key_path"])
        report_path = root / "generated_reports" / f"{case['case_id']}.json"
        report = load_json(report_path) if report_path.exists() else {"findings": [], "missing_report": True}
        frozen = validate_frozen_before_scoring(report)
        findings = report.get("findings", [])
        all_findings += len(findings)
        if expected.get("is_patched_control"):
            ready = [f for f in findings if is_report_ready(f)]
            false_positive += len(ready)
            ok = not ready
            per_case.append({"case_id": case["case_id"], "split": split_name, "expected_class": "none", "detected": bool(findings), "correct_root_cause": ok, "correct_file_function": ok, "report_quality": 0.0 if not findings else score_finding(findings[0])["score"], "frozen": frozen["status"]})
            continue
        match = match_case(expected, findings)
        found = bool(match["matched"])
        if found:
            detected += 1
            true_positive_findings += 1
            if match["strict_match"]:
                matched_strict += 1
            if "root_cause" in match["matched_fields"]:
                root_cause_correct += 1
            if "file" in match["matched_fields"] and "function" in match["matched_fields"]:
                correct_file_fn += 1
            matched_finding = next((f for f in findings if (f.get("id") or f.get("lead_id")) == match.get("finding_id")), findings[0])
            if str(matched_finding.get("severity")) == str(expected.get("expected_severity")):
                correct_severity += 1
            q = score_finding(matched_finding)["score"]
            total_quality += q
            quality_count += 1
            # Report-ready promotion requires executable PoC evidence. A source-only
            # reproduction narrative improves quality but must not make a finding
            # report-ready by itself.
            expected_ready = bool(matched_finding.get("poc", {}).get("assertion"))
            if is_report_ready(matched_finding) == expected_ready:
                report_ready_correct += 1
        else:
            missed += 1
            if expected.get("expected_severity") in CRITICAL:
                missed_critical += 1
            q = 0.0
        per_case.append({
            "case_id": case["case_id"],
            "split": split_name,
            "expected_class": expected.get("bug_class") or "none",
            "detected": found,
            "strict_match": match.get("strict_match", False),
            "correct_root_cause": "root_cause" in match.get("matched_fields", []),
            "correct_file_function": "file" in match.get("matched_fields", []) and "function" in match.get("matched_fields", []),
            "report_quality": q,
            "frozen": frozen["status"],
            "wrong_fields": match.get("wrong_fields", []),
        })
    total_vuln = sum(1 for c in cases if not load_json(root / c["answer_key_path"]).get("is_patched_control"))
    precision_den = true_positive_findings + max(0, all_findings - true_positive_findings)
    return {
        "case_count": len(cases),
        "vulnerable_case_count": total_vuln,
        "detected_count": detected,
        "missed_count": missed,
        "false_positive_count": false_positive,
        "recall": detected / (total_vuln or 1),
        "precision": true_positive_findings / (precision_den or 1),
        "severity_accuracy": correct_severity / (detected or 1),
        "file_function_accuracy": correct_file_fn / (total_vuln or 1),
        "root_cause_accuracy": root_cause_correct / (total_vuln or 1),
        "report_ready_accuracy": report_ready_correct / (detected or 1),
        "average_report_quality_score": round(total_quality / (quality_count or 1), 2),
        "missed_critical_count": missed_critical,
        "strict_match_count": matched_strict,
        "per_case": per_case,
    }


def score_ood(root: Path) -> dict[str, Any]:
    manifest = load_json(root / "corpus_manifest.json")
    cases = manifest.get("cases", [])
    calibration = [c for c in cases if c.get("corpus_split") == "vulnerable"]
    patched = [c for c in cases if c.get("corpus_split") == "patched"]
    holdout = [c for c in cases if c.get("corpus_split") == "holdout"]
    cal = score_split(calibration, root, split_name="calibration")
    pat = score_split(patched, root, split_name="patched")
    hold = score_split(holdout, root, split_name="holdout")
    answer_leak = False
    network = secrets = broadcasts = False
    for report_path in sorted((root / "generated_reports").glob("case_*.json")):
        report = load_json(report_path)
        answer_leak = answer_leak or bool(report.get("answer_key_loaded") or report.get("answer_key_read_during_detection"))
        network = network or bool(report.get("network_used"))
        secrets = secrets or bool(report.get("secrets_accessed"))
        broadcasts = broadcasts or bool(report.get("broadcasts_used"))
    bug_classes = {load_json(root / c["answer_key_path"]).get("bug_class") for c in calibration + holdout}
    bug_classes.discard(None)
    protocol_types = {c.get("protocol_type") for c in cases}
    vulnerable_total = cal["vulnerable_case_count"] + hold["vulnerable_case_count"]
    detected_total = cal["detected_count"] + hold["detected_count"]
    return {
        "status": "PASS",
        "calibration_case_count": len(calibration),
        "holdout_case_count": len(holdout),
        "patched_case_count": len(patched),
        "bug_class_count": len(bug_classes),
        "protocol_type_count": len(protocol_types),
        "calibration_detected_count": cal["detected_count"],
        "calibration_missed_count": cal["missed_count"],
        "holdout_detected_count": hold["detected_count"],
        "holdout_missed_count": hold["missed_count"],
        "patched_false_positive_count": pat["false_positive_count"],
        "calibration_recall": cal["recall"],
        "calibration_precision": cal["precision"],
        "holdout_recall": hold["recall"],
        "holdout_precision": hold["precision"],
        "patched_false_positive_rate": pat["false_positive_count"] / (len(patched) or 1),
        "severity_accuracy": (cal["severity_accuracy"] * cal["detected_count"] + hold["severity_accuracy"] * hold["detected_count"]) / (detected_total or 1),
        "file_function_accuracy": (cal["file_function_accuracy"] * cal["vulnerable_case_count"] + hold["file_function_accuracy"] * hold["vulnerable_case_count"]) / (vulnerable_total or 1),
        "root_cause_accuracy": (cal["root_cause_accuracy"] * cal["vulnerable_case_count"] + hold["root_cause_accuracy"] * hold["vulnerable_case_count"]) / (vulnerable_total or 1),
        "report_ready_accuracy": (cal["report_ready_accuracy"] * cal["detected_count"] + hold["report_ready_accuracy"] * hold["detected_count"]) / (detected_total or 1),
        "average_report_quality_score": round((cal["average_report_quality_score"] * cal["detected_count"] + hold["average_report_quality_score"] * hold["detected_count"]) / (detected_total or 1), 2),
        "missed_critical_count": hold["missed_critical_count"],
        "answer_key_leakage_detected": answer_leak,
        "network_used": network,
        "secrets_accessed": secrets,
        "broadcasts_used": broadcasts,
        "calibration": cal,
        "holdout": hold,
        "patched": pat,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Score frozen OOD generated reports")
    p.add_argument("root")
    args = p.parse_args(argv)
    result = score_ood(Path(args.root))
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
