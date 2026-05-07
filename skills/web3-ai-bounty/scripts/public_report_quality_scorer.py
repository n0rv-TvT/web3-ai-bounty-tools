#!/usr/bin/env python3
"""Public historical report quality scorer."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from report_quality_scorer import score_finding, score_report


def public_score_finding(finding: dict[str, Any]) -> dict[str, Any]:
    result = score_finding(finding)
    result["public_production_quality"] = result["score"] >= 8.0
    return result


def public_score_report(report: dict[str, Any]) -> dict[str, Any]:
    result = score_report(report)
    result["public_production_quality_count"] = sum(1 for row in result.get("findings", []) if row.get("score", 0) >= 8)
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Score public historical generated report quality")
    p.add_argument("report_json")
    args = p.parse_args(argv)
    report = json.loads(Path(args.report_json).read_text(errors="replace"))
    print(json.dumps(public_score_report(report), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
