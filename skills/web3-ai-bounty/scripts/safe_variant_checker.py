#!/usr/bin/env python3
"""Safe-variant false-positive checker."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from blind_source_analyzer import analyze_project
from source_to_lead_converter import convert_analysis


def check_safe_variants(project_root: Path, *, include_tests: bool = False) -> dict[str, Any]:
    analysis = analyze_project(project_root, include_tests=include_tests)
    converted = convert_analysis(analysis, with_poc=include_tests, project_root=project_root)
    report_ready = [lead for lead in converted["leads"] if ((lead.get("pipeline") or {}).get("final_status") == "REPORT_READY")]
    return {"status": "PASS" if not report_ready else "FAIL", "lead_count": converted["lead_count"], "report_ready_false_positive_count": len(report_ready), "report_ready_false_positives": report_ready, "analysis": analysis}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Check safe variants for report-ready false positives")
    p.add_argument("project_root")
    p.add_argument("--include-tests", action="store_true")
    args = p.parse_args(argv)
    result = check_safe_variants(Path(args.project_root), include_tests=args.include_tests)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
