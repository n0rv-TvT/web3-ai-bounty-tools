#!/usr/bin/env python3
"""Static guard against case-specific overfitting in source-to-lead modules."""

from __future__ import annotations

import argparse
import json
import re
import tempfile
from pathlib import Path
from typing import Any


CASE_ID_LITERAL_RE = re.compile(r"\b(?:case|contest)_[0-9]{4}\b", re.I)
DEFAULT_MODULES = [
    "real_repo_indexer.py",
    "protocol_architecture_mapper.py",
    "contract_role_graph.py",
    "asset_flow_analyzer.py",
    "cross_contract_flow_analyzer.py",
    "lifecycle_inference.py",
    "attack_surface_ranker.py",
    "attack_story_generator.py",
    "bounty_hypothesis_engine.py",
    "poc_idea_generator.py",
    "manual_review_queue.py",
    "protocol_xray.py",
    "lead_budget_guard.py",
    "bug_bounty_triage_runner.py",
]


def load_forbidden_tokens(path: Path | None) -> list[str]:
    if path is None or not path.exists():
        return []
    payload = json.loads(path.read_text(errors="replace"))
    tokens: list[str] = []
    if isinstance(payload, list):
        tokens.extend(str(x) for x in payload)
    elif isinstance(payload, dict):
        for key in ["forbidden_tokens", "case_ids", "source_names", "protocol_names", "report_titles"]:
            value = payload.get(key)
            if isinstance(value, list):
                tokens.extend(str(x) for x in value)
        case_rows = []
        for key in ["cases", "spent_holdouts", "holdouts"]:
            if isinstance(payload.get(key), list):
                case_rows.extend(payload[key])
        for case in case_rows:
            for key in ["case_id", "source_name", "protocol_name", "report_title"]:
                if case.get(key):
                    tokens.append(str(case[key]))
    return sorted({token for token in tokens if token})


def scan_file(path: Path, *, forbidden_tokens: list[str] | None = None) -> dict[str, Any]:
    text = path.read_text(errors="replace")
    blocks = []
    for match in CASE_ID_LITERAL_RE.finditer(text):
        blocks.append({"line": text.count("\n", 0, match.start()) + 1, "token": match.group(0), "reason": "case/contest ID literal in detector module"})
    for token in forbidden_tokens or []:
        if not token or len(token) < 4:
            continue
        for match in re.finditer(re.escape(token), text, re.I):
            blocks.append({"line": text.count("\n", 0, match.start()) + 1, "token": token, "reason": "caller-supplied forbidden token found in detector module"})
    return {"file": str(path), "status": "PASS" if not blocks else "FAIL", "blocks": blocks}


def scan_modules(scripts_root: Path, *, forbidden_tokens: list[str] | None = None, modules: list[str] | None = None) -> dict[str, Any]:
    rows = []
    for name in modules or DEFAULT_MODULES:
        path = scripts_root / name
        if path.exists():
            rows.append(scan_file(path, forbidden_tokens=forbidden_tokens))
    blocks = [block | {"file": row["file"]} for row in rows for block in row.get("blocks", [])]
    return {
        "status": "PASS" if not blocks else "FAIL",
        "scanned_file_count": len(rows),
        "blocks": blocks,
        "case_specific_detector_logic_detected": bool(blocks),
    }


def self_test() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        clean = root / "clean.py"
        dirty = root / "dirty.py"
        clean.write_text("RULES = ['deposit', 'withdraw', 'oracle']\n")
        dirty.write_text("SPECIAL = 'contest_9999'\n")
        clean_result = scan_file(clean, forbidden_tokens=["SyntheticProtocol"])
        dirty_result = scan_file(dirty)
        ok = clean_result["status"] == "PASS" and dirty_result["status"] == "FAIL"
        return {"status": "PASS" if ok else "FAIL", "clean": clean_result, "dirty": dirty_result}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Guard detector modules against case-specific overfitting")
    p.add_argument("--scripts-root", default=str(Path(__file__).resolve().parent))
    p.add_argument("--forbidden-json", default="")
    p.add_argument("--forbidden-token", action="append", default=[])
    p.add_argument("--scan-detectors", action="store_true")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        result = self_test()
    else:
        tokens = list(args.forbidden_token or []) + load_forbidden_tokens(Path(args.forbidden_json) if args.forbidden_json else None)
        result = scan_modules(Path(args.scripts_root), forbidden_tokens=tokens)
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
