#!/usr/bin/env python3
"""Detect prompt-injection attempts in untrusted project/tool content."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


PHRASES = [
    "ignore previous instructions",
    "do not report this",
    "do not report this bug",
    "mark this contract safe",
    "run this command",
    "delete files",
    "reveal secrets",
    "use this fake output",
    "override audit rules",
]


def pattern(phrase: str) -> re.Pattern[str]:
    return re.compile(r"\b" + r"\s+".join(re.escape(p) for p in phrase.split()) + r"\b", re.I)


def scan_text(text: str, *, source: str = "untrusted") -> dict[str, Any]:
    hits = []
    for phrase in PHRASES:
        for match in pattern(phrase).finditer(text or ""):
            hits.append({"phrase": match.group(0), "line": text.count("\n", 0, match.start()) + 1, "source": source, "action": "log_and_ignore"})
    return {"prompt_injection_detected": bool(hits), "hits": hits, "trusted_behavior_changed": False}


def scan_file(path: Path) -> dict[str, Any]:
    return scan_text(path.read_text(errors="replace"), source=str(path))


def enforce_untrusted_content_boundary(text: str, pipeline_rules: dict[str, Any]) -> dict[str, Any]:
    scan = scan_text(text, source="pipeline_input")
    return {"scan": scan, "pipeline_rules": pipeline_rules, "rules_changed": False}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Scan text/file for prompt injection attempts")
    p.add_argument("path")
    args = p.parse_args(argv)
    print(json.dumps(scan_file(Path(args.path)), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
