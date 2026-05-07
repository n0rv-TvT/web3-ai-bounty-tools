#!/usr/bin/env python3
"""Convenience entry point for fresh holdout miss analysis."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from fresh_holdout_scoring import score_split
from frozen_output_loader import PUBLIC_ROOT


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Generate fresh holdout miss analysis")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="fresh-holdout")
    p.add_argument("--frozen-only", action="store_true")
    args = p.parse_args(argv)
    result = score_split(Path(args.root), split=args.split, frozen_only=True)
    summary = {"status": result["status"], "miss_analysis_path": result.get("miss_analysis_path"), "miss_analysis_summary": result.get("miss_analysis_summary", {})}
    print(json.dumps(summary, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
