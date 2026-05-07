#!/usr/bin/env python3
"""Classify Web3 audit command execution safety."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SAFE_READ_ONLY = "SAFE_READ_ONLY"
SAFE_LOCAL_TEST = "SAFE_LOCAL_TEST"
SAFE_LOCAL_FORK_READONLY = "SAFE_LOCAL_FORK_READONLY"
NEEDS_USER_RPC_CONFIRMATION = "NEEDS_USER_RPC_CONFIRMATION"
NEEDS_USER_NETWORK_CONFIRMATION = "NEEDS_USER_NETWORK_CONFIRMATION"
REVIEW_REQUIRED = "REVIEW_REQUIRED"
BLOCKED_BROADCAST = "BLOCKED_BROADCAST"
BLOCKED_SECRET_REQUIRED = "BLOCKED_SECRET_REQUIRED"
BLOCKED_PRODUCTION_ACTION = "BLOCKED_PRODUCTION_ACTION"
BLOCKED_DESTRUCTIVE_COMMAND = "BLOCKED_DESTRUCTIVE_COMMAND"
BLOCKED_DEPENDENCY_INSTALL = "BLOCKED_DEPENDENCY_INSTALL"
BLOCKED_ENV_ACCESS = "BLOCKED_ENV_ACCESS"

ALLOWED = {SAFE_READ_ONLY, SAFE_LOCAL_TEST}
NEEDS_CONFIRMATION = {SAFE_LOCAL_FORK_READONLY, NEEDS_USER_RPC_CONFIRMATION, NEEDS_USER_NETWORK_CONFIRMATION, REVIEW_REQUIRED}


def result(
    operation: str,
    operation_type: str,
    classification: str,
    reasons: list[str],
    blocked: list[str] | None = None,
    safe_alternative: str | None = None,
) -> dict[str, Any]:
    requires = classification in NEEDS_CONFIRMATION
    allowed = classification in ALLOWED
    if classification.startswith("BLOCKED_"):
        next_action = "stop"
    elif requires:
        next_action = "ask user for explicit confirmation or use safe alternative"
    elif allowed:
        next_action = "execute only if requested"
    else:
        next_action = "review manually"
    return {
        "execution_safety": {
            "schema_version": "web3-execution-safety/v1",
            "operation": operation,
            "operation_type": operation_type,
            "classification": classification,
            "allowed_to_execute": allowed,
            "requires_user_confirmation": requires,
            "reasons": list(dict.fromkeys(reasons)),
            "blocked_capabilities": blocked or [],
            "safe_alternative": safe_alternative,
            "next_action": next_action,
        }
    }


def classify_command(command: str) -> dict[str, Any]:
    c = " ".join(command.strip().split())
    lower = c.lower()
    if not c:
        return result(c, "unknown", REVIEW_REQUIRED, ["empty command"])
    if re.search(r"\bcast\s+send\b|\bforge\s+script\b.*--broadcast|--broadcast\b|\beth_sendrawtransaction\b", lower):
        return result(c, "command", BLOCKED_BROADCAST, ["command may broadcast or mutate chain state"], ["chain_state_mutation"], "use fork/local simulation without --broadcast")
    if re.search(r"\brm\s+(-rf|-fr|-[^ ]*r[^ ]*f)|\bgit\s+reset\b|\bgit\s+push\s+--force|\bsudo\b|\bchmod\s+-r\b", lower):
        return result(c, "command", BLOCKED_DESTRUCTIVE_COMMAND, ["destructive local/system command"], ["local_data_loss"])
    if re.search(r"\b(printenv|env|set)\b", lower):
        return result(c, "command", BLOCKED_ENV_ACCESS, ["command can print environment variables"], ["secret_exposure"])
    if any(token in lower for token in ["private_key", "mnemonic", "seed phrase", "keystore", ".env", "bearer ", "cookie"]):
        return result(c, "command", BLOCKED_SECRET_REQUIRED, ["command references secret-bearing material"], ["secret_access"])
    if re.search(r"\b(npm|yarn|pnpm|pip|pip3|apt|apt-get|brew)\s+(install|add|upgrade)\b", lower):
        return result(c, "command", BLOCKED_DEPENDENCY_INSTALL, ["dependency installation changes local environment"], ["dependency_install"], "ask user before installing dependencies")
    if re.search(r"\bforge\s+test\b|\bnpm\s+test\b|\byarn\s+test\b|\bpnpm\s+test\b|\bpytest\b", lower):
        if any(token in lower for token in ["--fork-url", "http://", "https://"]):
            return result(c, "poc_execution", NEEDS_USER_RPC_CONFIRMATION, ["test uses fork/RPC or URL"], [], "run a local deterministic test first")
        return result(c, "poc_execution", SAFE_LOCAL_TEST, ["local test command without obvious network/broadcast/secret access"])
    if re.search(r"\bcast\s+(call|storage|code|balance)\b|--rpc-url\b|\brpc-url\b", lower):
        return result(c, "rpc", NEEDS_USER_RPC_CONFIRMATION, ["read-only RPC command requires user-approved endpoint"])
    if re.search(r"\b(curl|wget|gh\s+api)\b", lower):
        return result(c, "network", NEEDS_USER_NETWORK_CONFIRMATION, ["network command requires explicit authorization"])
    if re.search(r"\b(mkdir|touch|cp|mv|python3?\b.*>.*|apply_patch)\b", lower):
        return result(c, "file_write", REVIEW_REQUIRED, ["command may modify local files"])
    return result(c, "command", SAFE_READ_ONLY, ["no dangerous execution pattern detected"])


def classify_file(path: str, write: bool = False) -> dict[str, Any]:
    p = Path(path)
    text = str(p).lower()
    name = p.name.lower()
    if name == ".env" or name.startswith(".env.") or any(token in text for token in ["private_key", "privatekey", "mnemonic", "keystore", "wallet", "cookie", "token"]):
        return result(path, "file_write" if write else "file_read", BLOCKED_SECRET_REQUIRED, ["secret-bearing file path"], ["secret_access"])
    if write:
        if any(part in text for part in ["/src/", "/contracts/", "src/", "contracts/"]):
            return result(path, "file_write", BLOCKED_PRODUCTION_ACTION, ["would modify production contract/source path"], ["production_source_modification"], "write tests, harnesses, notes, or reports instead")
        return result(path, "file_write", REVIEW_REQUIRED, ["local file write requires review"])
    return result(path, "file_read", SAFE_READ_ONLY, ["local non-secret file read"])


def self_test() -> dict[str, Any]:
    checks = [
        classify_command("forge test --match-test test_exploit -vvvv")["execution_safety"]["classification"] == SAFE_LOCAL_TEST,
        classify_command("forge test --fork-url $RPC_URL")["execution_safety"]["classification"] == NEEDS_USER_RPC_CONFIRMATION,
        classify_command("cast send 0x0")["execution_safety"]["classification"] == BLOCKED_BROADCAST,
        classify_command("printenv")["execution_safety"]["classification"] == BLOCKED_ENV_ACCESS,
        classify_file(".env")["execution_safety"]["classification"] == BLOCKED_SECRET_REQUIRED,
    ]
    return {"status": "PASS" if all(checks) else "FAIL", "checks_passed": sum(bool(c) for c in checks), "checks_total": len(checks)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Classify Web3 execution safety")
    parser.add_argument("--command")
    parser.add_argument("--file")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--json-out")
    args = parser.parse_args(argv)
    if args.self_test:
        payload = self_test()
    elif args.command:
        payload = classify_command(args.command)
    elif args.file:
        payload = classify_file(args.file, write=args.write)
    else:
        payload = result("", "unknown", REVIEW_REQUIRED, ["no operation supplied"])
    text = json.dumps(payload, indent=2)
    if args.json_out:
        Path(args.json_out).write_text(text + "\n")
    print(text)
    safety = payload.get("execution_safety", {})
    return 0 if payload.get("status") == "PASS" or safety.get("allowed_to_execute") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
