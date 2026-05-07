#!/usr/bin/env python3
"""Strict root-cause matcher for generated OOD findings."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


STRICT_FIELDS = ["bug_class", "root_cause", "file", "function", "affected_asset", "exploit_path", "impact"]


def first_rule(finding: dict[str, Any]) -> str:
    for key in ["external_evidence", "blind_evidence", "evidence"]:
        evidence = finding.get(key) or []
        if evidence and evidence[0].get("rule"):
            return str(evidence[0]["rule"])
    return str(finding.get("root_cause_rule") or "")


def impact_type(finding: dict[str, Any]) -> str:
    impact = finding.get("impact")
    if isinstance(impact, dict):
        return str(impact.get("type") or "")
    return str(impact or "")


def token_match(tokens: list[str], text: str) -> bool:
    lowered = text.lower()
    return all(token.lower() in lowered for token in tokens)


def match_fields(expected: dict[str, Any], finding: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    matched: list[str] = []
    missing: list[str] = []
    wrong: list[str] = []
    checks = {
        "bug_class": str(finding.get("bug_class")) == str(expected.get("bug_class")),
        "root_cause": first_rule(finding) == str(expected.get("root_cause_rule")),
        "file": str(finding.get("file_path")) == str(expected.get("source_file")),
        "function": str(finding.get("function")) == str(expected.get("affected_function")),
        "affected_asset": str(finding.get("affected_asset")) == str(expected.get("affected_asset")),
        "exploit_path": token_match(expected.get("exploit_path_tokens", []), str(finding.get("exploit_scenario") or "")),
        "impact": impact_type(finding) == str(expected.get("impact_type")),
    }
    for field in STRICT_FIELDS:
        if checks[field]:
            matched.append(field)
        elif not expected.get(field) and field not in {"file", "function", "root_cause", "impact", "affected_asset", "bug_class", "exploit_path"}:
            missing.append(field)
        else:
            wrong.append(field)
    return matched, missing, wrong


def match_case(expected: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    best: dict[str, Any] | None = None
    best_fields: list[str] = []
    best_missing: list[str] = []
    best_wrong: list[str] = STRICT_FIELDS.copy()
    for finding in findings:
        matched, missing, wrong = match_fields(expected, finding)
        if len(matched) > len(best_fields):
            best = finding
            best_fields, best_missing, best_wrong = matched, missing, wrong
    strict = best is not None and set(best_fields) == set(STRICT_FIELDS)
    partial = best is not None and not strict and "bug_class" in best_fields and "root_cause" in best_fields
    return {
        "case_id": expected.get("case_id"),
        "matched": bool(strict or partial),
        "strict_match": bool(strict),
        "partial_match": bool(partial),
        "matched_fields": best_fields,
        "missing_fields": best_missing,
        "wrong_fields": best_wrong,
        "finding_id": (best or {}).get("id") or (best or {}).get("lead_id"),
        "notes": "strict root-cause match" if strict else ("partial root-cause match" if partial else "no compatible finding"),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Match a generated finding report to one expected finding")
    p.add_argument("expected_json")
    p.add_argument("generated_report_json")
    args = p.parse_args(argv)
    expected = json.loads(Path(args.expected_json).read_text(errors="replace"))
    report = json.loads(Path(args.generated_report_json).read_text(errors="replace"))
    print(json.dumps(match_case(expected, report.get("findings", [])), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
