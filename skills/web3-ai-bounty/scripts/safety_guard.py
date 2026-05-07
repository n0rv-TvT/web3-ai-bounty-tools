#!/usr/bin/env python3
"""Classify audit commands and file accesses before execution."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


SAFE_READ_ONLY = "SAFE_READ_ONLY"
READ_ONLY_SENSITIVE = "READ_ONLY_SENSITIVE"
EXECUTES_UNTRUSTED_CODE = "EXECUTES_UNTRUSTED_CODE"
MODIFIES_FILES = "MODIFIES_FILES"
REQUIRES_NETWORK = "REQUIRES_NETWORK"
POTENTIALLY_DESTRUCTIVE = "POTENTIALLY_DESTRUCTIVE"
FORBIDDEN = "FORBIDDEN"


def classify_file_access(path: str) -> dict[str, str]:
    p = Path(path)
    name = p.name.lower()
    text = str(p).lower()
    if name == ".env" or name.startswith(".env.") or any(x in text for x in ["privatekey", "private_key", "mnemonic", "keystore", "wallet"]):
        return {"classification": FORBIDDEN, "reason": "secret-bearing file access is forbidden"}
    if name.endswith((".toml", ".json", ".yaml", ".yml")) or "config" in text:
        return {"classification": READ_ONLY_SENSITIVE, "reason": "configuration may contain sensitive endpoints or tokens"}
    return {"classification": SAFE_READ_ONLY, "reason": "source/document read is allowed"}


def classify_command(command: str) -> dict[str, str]:
    c = " ".join(command.strip().split())
    lower = c.lower()
    forbidden_patterns = [r"\bcast\s+send\b", r"\bforge\s+script\b.*--broadcast\b", r"\brm\s+(-rf|-fr|-[^ ]*r[^ ]*f)", r"\bgit\s+reset\b", r"\bgit\s+push\s+--force", r"\bnpm\s+i\s+-g\b", r"\bpip\s+install\b.*\s--user\b"]
    if any(re.search(p, lower) for p in forbidden_patterns):
        return {"classification": FORBIDDEN, "reason": "command is forbidden without explicit approval"}
    if re.search(r"\b(printenv|env|set)\b", lower):
        return {"classification": FORBIDDEN, "reason": "printing environment variables is forbidden"}
    if re.search(r"\b(curl|wget|gh\s+api|cast\s+call|cast\s+storage)\b", lower):
        return {"classification": REQUIRES_NETWORK, "reason": "command may require network access"}
    if re.search(r"\b(forge\s+test|npm\s+test|yarn\s+test|pytest)\b", lower):
        return {"classification": EXECUTES_UNTRUSTED_CODE, "reason": "test command executes project code"}
    if re.search(r"\b(mkdir|touch|cp|mv|apply_patch)\b", lower):
        return {"classification": MODIFIES_FILES, "reason": "command modifies local files"}
    return {"classification": SAFE_READ_ONLY, "reason": "no dangerous pattern detected"}


def self_test() -> dict[str, object]:
    checks = [
        classify_file_access(".env")["classification"] == FORBIDDEN,
        classify_command("cast send 0x0")["classification"] == FORBIDDEN,
        classify_command("forge script Deploy --broadcast")["classification"] == FORBIDDEN,
        classify_command("forge test")["classification"] == EXECUTES_UNTRUSTED_CODE,
    ]
    return {"status": "PASS" if all(checks) else "FAIL", "checks_passed": sum(1 for c in checks if c), "checks_total": len(checks)}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Classify command/file safety")
    p.add_argument("--command")
    p.add_argument("--file")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        result = self_test()
    elif args.command:
        result = classify_command(args.command)
    elif args.file:
        result = classify_file_access(args.file)
    else:
        result = {"classification": SAFE_READ_ONLY, "reason": "no operation"}
    print(json.dumps(result, indent=2))
    return 0 if result.get("status", "PASS") == "PASS" and result.get("classification") != FORBIDDEN else 1


if __name__ == "__main__":
    raise SystemExit(main())
