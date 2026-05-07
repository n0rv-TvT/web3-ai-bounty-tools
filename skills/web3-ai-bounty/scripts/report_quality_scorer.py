#!/usr/bin/env python3
"""Score generated audit findings for evidence and report quality."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def has_evidence(finding: dict[str, Any]) -> bool:
    return bool(finding.get("external_evidence") or finding.get("blind_evidence") or finding.get("evidence"))


def score_finding(finding: dict[str, Any]) -> dict[str, Any]:
    checks = {
        "file_function_evidence": bool(finding.get("file_path") and finding.get("function") and has_evidence(finding)),
        "code_path_clarity": bool(finding.get("code_path")),
        "attacker_capability": bool(finding.get("attacker_capabilities") or finding.get("attacker_capability")),
        "affected_asset": bool(finding.get("affected_asset")),
        "exploit_scenario": len(str(finding.get("exploit_scenario") or "")) >= 40,
        "impact_explanation": bool((finding.get("impact") or {}).get("type") if isinstance(finding.get("impact"), dict) else finding.get("impact")),
        "likelihood_explanation": bool(finding.get("likelihood")),
        "severity_rationale": bool(finding.get("severity_rationale") or finding.get("severity")),
        "poc_or_reproduction": bool((finding.get("poc") or {}).get("assertion") or finding.get("reproduction")),
        "remediation_quality": bool(finding.get("fix") or finding.get("remediation")),
        "uncertainty_labeling": bool(finding.get("confidence") or finding.get("state")),
        "duplicate_root_cause_handling": bool(finding.get("root_cause_rule") or finding.get("severity_rationale")),
    }
    score = round(10.0 * sum(1 for ok in checks.values() if ok) / len(checks), 2)
    return {"score": score, "checks": checks, "production_quality": score >= 8.0}


def score_report(report: dict[str, Any]) -> dict[str, Any]:
    rows = []
    for finding in report.get("findings", []):
        scored = score_finding(finding)
        rows.append({"finding_id": finding.get("id") or finding.get("lead_id"), **scored})
    avg = round(sum(row["score"] for row in rows) / (len(rows) or 1), 2) if rows else 0.0
    return {"finding_count": len(rows), "average_report_quality_score": avg, "findings": rows}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Score generated finding report quality")
    p.add_argument("report_json")
    args = p.parse_args(argv)
    report = json.loads(Path(args.report_json).read_text(errors="replace"))
    print(json.dumps(score_report(report), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
