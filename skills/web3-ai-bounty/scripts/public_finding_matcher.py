#!/usr/bin/env python3
"""Public historical strict finding matcher."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from finding_matcher import match_case


def public_match_case(expected: dict[str, Any], generated_findings: list[dict[str, Any]]) -> dict[str, Any]:
    result = match_case(expected, generated_findings)
    result.setdefault("notes", "")
    if not result["strict_match"] and result["partial_match"]:
        result["notes"] = "partial public historical match; not production-counted"
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Match public generated finding to expected historical answer")
    p.add_argument("expected_json")
    p.add_argument("generated_report_json")
    args = p.parse_args(argv)
    expected = json.loads(Path(args.expected_json).read_text(errors="replace"))
    report = json.loads(Path(args.generated_report_json).read_text(errors="replace"))
    print(json.dumps(public_match_case(expected, report.get("findings", [])), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
