#!/usr/bin/env python3
"""Scoring for public historical benchmark cases."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from public_answer_key_guard import validate_report_before_scoring
from public_finding_matcher import public_match_case
from public_report_quality_scorer import public_score_finding


PUBLIC_ROOT = Path(__file__).resolve().parents[1] / "benchmarks" / "public-historical-corpus"
CRITICAL = {"Critical", "CRITICAL"}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace"))


def is_report_ready(finding: dict[str, Any]) -> bool:
    return bool(finding.get("report_ready") or (finding.get("pipeline") or {}).get("final_status") == "REPORT_READY" or finding.get("state") == "REPORT_READY")


def expected_finding_rows(expected: dict[str, Any]) -> list[dict[str, Any]]:
    rows = expected.get("all_expected_findings")
    if isinstance(rows, list) and rows:
        normalized: list[dict[str, Any]] = []
        for idx, row in enumerate(rows, start=1):
            merged = {k: v for k, v in expected.items() if k != "all_expected_findings"}
            merged.update(row)
            merged.setdefault("case_id", expected.get("case_id"))
            merged.setdefault("finding_id", row.get("finding_id") or f"expected_{idx:04d}")
            normalized.append(merged)
        return normalized
    return [expected]


def zero_metrics(root: Path, *, status: str = "BLOCKED") -> dict[str, Any]:
    return {
        "status": status,
        "public_case_import_status": "blocked_pending_approved_public_case_sources",
        "public_vulnerable_case_count": 0,
        "public_patched_case_count": 0,
        "public_holdout_case_count": 0,
        "public_bug_class_count": 0,
        "public_protocol_type_count": 0,
        "public_calibration_detected_count": 0,
        "public_calibration_missed_count": 0,
        "public_holdout_detected_count": 0,
        "public_holdout_missed_count": 0,
        "public_patched_false_positive_count": 0,
        "public_calibration_recall": 0.0,
        "public_calibration_precision": 0.0,
        "public_holdout_recall": 0.0,
        "public_holdout_precision": 0.0,
        "public_holdout_finding_expected_count": 0,
        "public_holdout_finding_strict_match_count": 0,
        "public_holdout_finding_recall": 0.0,
        "public_holdout_finding_precision": 0.0,
        "public_patched_false_positive_rate": 0.0,
        "public_severity_accuracy": 0.0,
        "public_file_function_accuracy": 0.0,
        "public_root_cause_accuracy": 0.0,
        "public_report_ready_accuracy": 0.0,
        "public_average_report_quality_score": 0.0,
        "public_missed_critical_count": 0,
        "answer_key_leakage_detected": False,
        "writeup_leakage_detected": False,
        "network_used_during_detection": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "per_case": [],
    }


def score_public_benchmark(root: Path = PUBLIC_ROOT) -> dict[str, Any]:
    manifest_path = root / "corpus_manifest.json"
    if not manifest_path.exists():
        return zero_metrics(root)
    manifest = load_json(manifest_path)
    cases = manifest.get("cases", [])
    if not cases:
        return zero_metrics(root)
    cal_cases = [c for c in cases if c.get("is_vulnerable") and not c.get("is_holdout") and not c.get("is_patched_control")]
    holdout_cases = [c for c in cases if c.get("is_holdout")]
    patched_cases = [c for c in cases if c.get("is_patched_control")]
    bug_classes: set[str] = set()
    protocols = {c.get("protocol_type") for c in cases if c.get("protocol_type")}
    per_case: list[dict[str, Any]] = []
    totals = {"detected_cal": 0, "detected_hold": 0, "miss_cal": 0, "miss_hold": 0, "fp_patch": 0, "severity": 0, "file_fn": 0, "root": 0, "ready": 0, "quality": 0.0, "quality_count": 0, "missed_critical": 0, "answer_leak": False, "writeup_leak": False, "network": False, "secrets": False, "broadcasts": False, "hold_expected_findings": 0, "hold_strict_findings": 0, "hold_generated_findings": 0}

    def process_vulnerable(case: dict[str, Any], split: str) -> None:
        expected = load_json(root / case["answer_key_path"])
        expected_rows = expected_finding_rows(expected)
        for row in expected_rows:
            if row.get("bug_class"):
                bug_classes.add(row["bug_class"])
        report_path = root / "generated_reports" / f"{case['case_id']}.json"
        report = load_json(report_path) if report_path.exists() else {"findings": []}
        guard = validate_report_before_scoring(report) if report_path.exists() else {"status": "FAIL", "blocks": ["missing frozen report"]}
        totals["answer_leak"] = totals["answer_leak"] or bool(report.get("answer_key_loaded") or report.get("answer_key_read_during_detection"))
        totals["writeup_leak"] = totals["writeup_leak"] or bool(report.get("writeup_read_during_detection"))
        totals["network"] = totals["network"] or bool(report.get("network_used"))
        totals["secrets"] = totals["secrets"] or bool(report.get("secrets_accessed"))
        totals["broadcasts"] = totals["broadcasts"] or bool(report.get("broadcasts_used"))
        findings = report.get("findings", [])
        matches = [public_match_case(row, findings) for row in expected_rows]
        strict_matches = [m for m in matches if m["strict_match"]]
        detected = bool(strict_matches)
        if split == "holdout":
            totals["hold_expected_findings"] += len(expected_rows)
            totals["hold_strict_findings"] += len(strict_matches)
            totals["hold_generated_findings"] += len(findings)
        if split == "calibration":
            totals["detected_cal"] += int(detected)
            totals["miss_cal"] += int(not detected)
        else:
            totals["detected_hold"] += int(detected)
            totals["miss_hold"] += int(not detected)
            totals["missed_critical"] += sum(1 for row, match in zip(expected_rows, matches) if not match["strict_match"] and row.get("expected_severity") in CRITICAL)
        q = 0.0
        first_strict = strict_matches[0] if strict_matches else (matches[0] if matches else {"matched_fields": []})
        first_expected = expected_rows[0] if expected_rows else expected
        if strict_matches:
            matched_finding_id = first_strict.get("finding_id")
            finding = next((f for f in findings if (f.get("id") or f.get("lead_id")) == matched_finding_id), findings[0] if findings else {})
            q = public_score_finding(finding)["score"]
            totals["quality"] += q
            totals["quality_count"] += 1
            totals["severity"] += int(str(finding.get("severity")) == str(first_expected.get("expected_severity")))
            totals["file_fn"] += int("file" in first_strict["matched_fields"] and "function" in first_strict["matched_fields"])
            totals["root"] += int("root_cause" in first_strict["matched_fields"])
            totals["ready"] += int(is_report_ready(finding) == bool((finding.get("poc") or {}).get("assertion")))
        per_case.append({"case_id": case["case_id"], "split": split, "public_source": case.get("source_name"), "expected_class": first_expected.get("bug_class"), "expected_finding_count": len(expected_rows), "strict_finding_matches": len(strict_matches), "generated_finding_count": len(findings), "detected": detected, "correct_root_cause": "root_cause" in first_strict.get("matched_fields", []), "correct_file_function": "file" in first_strict.get("matched_fields", []) and "function" in first_strict.get("matched_fields", []), "report_quality": q, "guard_status": guard["status"]})

    for case in cal_cases:
        process_vulnerable(case, "calibration")
    for case in holdout_cases:
        process_vulnerable(case, "holdout")
    for case in patched_cases:
        report_path = root / "generated_reports" / f"{case['case_id']}.json"
        report = load_json(report_path) if report_path.exists() else {"findings": []}
        ready = [f for f in report.get("findings", []) if is_report_ready(f)]
        totals["fp_patch"] += len(ready)
        per_case.append({"case_id": case["case_id"], "split": "patched", "public_source": case.get("source_name"), "expected_class": "none", "detected": bool(report.get("findings")), "correct_root_cause": not ready, "correct_file_function": not ready, "report_quality": 0.0})
    vuln_total = len(cal_cases) + len(holdout_cases)
    detected_total = totals["detected_cal"] + totals["detected_hold"]
    result = {
        "status": "PASS",
        "public_case_import_status": manifest.get("public_case_import_status", "unknown"),
        "public_vulnerable_case_count": len(cal_cases),
        "public_patched_case_count": len(patched_cases),
        "public_holdout_case_count": len(holdout_cases),
        "public_bug_class_count": len(bug_classes),
        "public_protocol_type_count": len(protocols),
        "public_calibration_detected_count": totals["detected_cal"],
        "public_calibration_missed_count": totals["miss_cal"],
        "public_holdout_detected_count": totals["detected_hold"],
        "public_holdout_missed_count": totals["miss_hold"],
        "public_patched_false_positive_count": totals["fp_patch"],
        "public_calibration_recall": totals["detected_cal"] / (len(cal_cases) or 1),
        "public_calibration_precision": totals["detected_cal"] / ((totals["detected_cal"] + max(0, len(cal_cases) - totals["detected_cal"])) or 1),
        "public_holdout_recall": totals["detected_hold"] / (len(holdout_cases) or 1),
        "public_holdout_precision": totals["detected_hold"] / ((totals["detected_hold"] + max(0, len(holdout_cases) - totals["detected_hold"])) or 1),
        "public_holdout_finding_expected_count": totals["hold_expected_findings"],
        "public_holdout_finding_strict_match_count": totals["hold_strict_findings"],
        "public_holdout_finding_recall": totals["hold_strict_findings"] / (totals["hold_expected_findings"] or 1),
        "public_holdout_finding_precision": totals["hold_strict_findings"] / (totals["hold_generated_findings"] or 1),
        "public_patched_false_positive_rate": totals["fp_patch"] / (len(patched_cases) or 1),
        "public_severity_accuracy": totals["severity"] / (detected_total or 1),
        "public_file_function_accuracy": totals["file_fn"] / (vuln_total or 1),
        "public_root_cause_accuracy": totals["root"] / (vuln_total or 1),
        "public_report_ready_accuracy": totals["ready"] / (detected_total or 1),
        "public_average_report_quality_score": round(totals["quality"] / (totals["quality_count"] or 1), 2),
        "public_missed_critical_count": totals["missed_critical"],
        "answer_key_leakage_detected": totals["answer_leak"],
        "writeup_leakage_detected": totals["writeup_leak"],
        "network_used_during_detection": totals["network"],
        "secrets_accessed": totals["secrets"],
        "broadcasts_used": totals["broadcasts"],
        "per_case": per_case,
    }
    (root / "scoring").mkdir(parents=True, exist_ok=True)
    (root / "scoring" / "public_score.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Score public historical benchmark")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    args = p.parse_args(argv)
    result = score_public_benchmark(Path(args.root))
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
