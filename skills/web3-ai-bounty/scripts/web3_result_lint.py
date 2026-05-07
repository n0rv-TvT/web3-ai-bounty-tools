#!/usr/bin/env python3
"""Extract and validate web3_result blocks from Opencode command output.

This is intentionally a small fail-closed linter for saved command transcripts.
It validates the generic web3_result schema by default and, with --strict,
also validates command-specific schemas for the high-risk report pipeline.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from schema_validator import validate_payload


FENCE_RE = re.compile(r"```(?P<lang>[A-Za-z0-9_-]*)\s*\n(?P<body>.*?)\n```", re.DOTALL)

COMMAND_SCHEMA = {
    "web3-hunt": "web3_hunt_result",
    "web3-poc": "web3_poc_result",
    "web3-validate": "web3_validate_result",
    "web3-report": "web3_report_result",
}


def extract_candidate_blocks(text: str) -> list[str]:
    blocks: list[str] = []
    for match in FENCE_RE.finditer(text):
        body = match.group("body").strip()
        if "web3_result" in body:
            blocks.append(body)
    if blocks:
        return blocks
    stripped = text.strip()
    if "web3_result" in stripped:
        return [stripped]
    return []


def parse_block(block: str) -> dict[str, Any]:
    try:
        parsed = json.loads(block)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore
        except ImportError as exc:  # pragma: no cover - dependency guard
            raise ValueError("PyYAML is required to parse YAML web3_result blocks") from exc
        parsed = yaml.safe_load(block)
    if not isinstance(parsed, dict):
        raise ValueError("web3_result block must parse to an object")
    return parsed


def validate_block(payload: dict[str, Any], strict: bool) -> list[str]:
    errors: list[str] = []
    generic = validate_payload("web3_result", payload)
    errors.extend(f"web3_result: {err}" for err in generic["errors"])

    if "execution_safety" in payload:
        safety = validate_payload("execution_safety", payload)
        errors.extend(f"execution_safety: {err}" for err in safety["errors"])

    command = (payload.get("web3_result") or {}).get("command")
    command_schema = COMMAND_SCHEMA.get(command)
    if strict and command_schema:
        strict_result = validate_payload(command_schema, payload)
        errors.extend(f"{command_schema}: {err}" for err in strict_result["errors"])
    return errors


def lint_text(text: str, *, source: str, strict: bool, require: bool) -> dict[str, Any]:
    blocks = extract_candidate_blocks(text)
    errors: list[str] = []
    parsed_blocks = 0
    commands: list[str] = []
    if require and not blocks:
        errors.append("missing web3_result block")
    for index, block in enumerate(blocks, start=1):
        try:
            payload = parse_block(block)
        except ValueError as exc:
            errors.append(f"block {index}: parse error: {exc}")
            continue
        parsed_blocks += 1
        command = (payload.get("web3_result") or {}).get("command")
        if command:
            commands.append(command)
        for err in validate_block(payload, strict=strict):
            errors.append(f"block {index}: {err}")
    return {
        "source": source,
        "valid": not errors,
        "blocks_found": len(blocks),
        "blocks_parsed": parsed_blocks,
        "commands": commands,
        "errors": errors,
    }


def self_test() -> dict[str, Any]:
    valid = """```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-score
  severity_mode: critical-bounty
  status: NEEDS_CONTEXT
  target: sample
  summary: sample target needs scope
  evidence_missing:
    - target scope
  next_action: /web3-scope sample
```"""
    invalid = """```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-report
  severity_mode: critical-bounty
  status: REPORT_READY
  target: sample
  summary: incomplete
  evidence_missing:
    - PoC assertion
  next_action: stop
```"""
    good = lint_text(valid, source="self-test-valid", strict=False, require=True)
    bad = lint_text(invalid, source="self-test-invalid", strict=False, require=True)
    checks = [good["valid"] is True, bad["valid"] is False, bool(bad["errors"])]
    return {
        "status": "PASS" if all(checks) else "FAIL",
        "checks_passed": sum(bool(check) for check in checks),
        "checks_total": len(checks),
        "valid_sample": good,
        "invalid_sample": bad,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lint web3_result blocks in command output")
    parser.add_argument("files", nargs="*", help="Saved command-output files to lint. Reads stdin when omitted.")
    parser.add_argument("--strict", action="store_true", help="Also apply command-specific schemas where available")
    parser.add_argument("--require", action="store_true", help="Fail when no web3_result block is present")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    parser.add_argument("--self-test", action="store_true", help="Run built-in linter self-test")
    args = parser.parse_args(argv)

    if args.self_test:
        result = self_test()
        print(json.dumps(result, indent=2))
        return 0 if result["status"] == "PASS" else 1

    reports: list[dict[str, Any]] = []
    if args.files:
        for file_name in args.files:
            path = Path(file_name)
            reports.append(lint_text(path.read_text(errors="replace"), source=str(path), strict=args.strict, require=args.require))
    else:
        reports.append(lint_text(sys.stdin.read(), source="stdin", strict=args.strict, require=args.require))

    ok = all(report["valid"] for report in reports)
    result = {"status": "PASS" if ok else "FAIL", "files_checked": len(reports), "reports": reports}
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for report in reports:
            print(f"{report['source']}: {'PASS' if report['valid'] else 'FAIL'} ({report['blocks_found']} block(s))")
            for err in report["errors"]:
                print(f"  - {err}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
