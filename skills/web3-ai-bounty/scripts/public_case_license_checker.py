#!/usr/bin/env python3
"""License/source metadata checks for public historical benchmark cases."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def check_case_license(case: dict[str, Any]) -> dict[str, Any]:
    blocks: list[str] = []
    if not case.get("source_name"):
        blocks.append("missing source_name")
    if case.get("source_type") != "local_mock" and not case.get("source_url"):
        blocks.append("public source missing source_url")
    if not case.get("license_note"):
        blocks.append("missing license_note")
    if not case.get("commit_hash"):
        blocks.append("missing commit_hash or not_applicable")
    return {"status": "PASS" if not blocks else "FAIL", "blocks": blocks, "case_id": case.get("case_id")}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Check public benchmark case license metadata")
    p.add_argument("case_json")
    args = p.parse_args(argv)
    case = json.loads(Path(args.case_json).read_text(errors="replace"))
    result = check_case_license(case)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
