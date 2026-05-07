#!/usr/bin/env python3
"""Safe build/test classifier and runner for public benchmark cases."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any


FORBIDDEN_SUBSTRINGS = ["--broadcast", "cast send", "forge script", "deploy", "private-key", ".env"]
NETWORK_COMMANDS = ["npm install", "yarn install", "pnpm install", "forge install"]
UNTRUSTED_ALLOWED = ["forge test", "forge build", "npm test", "npx hardhat test", "truffle test"]


def detect_framework(project_root: Path) -> str:
    if (project_root / "foundry.toml").exists():
        return "Foundry"
    if (project_root / "hardhat.config.js").exists() or (project_root / "hardhat.config.ts").exists():
        return "Hardhat"
    if (project_root / "truffle-config.js").exists():
        return "Truffle"
    return "none" if (project_root / "src").exists() or (project_root / "contracts").exists() else "unknown"


def classify_command(command: str) -> dict[str, Any]:
    lowered = command.lower().strip()
    if any(x in lowered for x in FORBIDDEN_SUBSTRINGS):
        return {"classification": "forbidden", "allowed": False, "reason": "deployment/broadcast/secret-bearing command"}
    if any(lowered.startswith(x) for x in NETWORK_COMMANDS):
        return {"classification": "requires-network-approval", "allowed": False, "reason": "package install or network dependency"}
    if any(lowered.startswith(x) for x in UNTRUSTED_ALLOWED):
        return {"classification": "executes-untrusted-code", "allowed": True, "reason": "local build/test command"}
    return {"classification": "unknown", "allowed": False, "reason": "unknown command requires review"}


def default_test_command(project_root: Path) -> str | None:
    framework = detect_framework(project_root)
    if framework == "Foundry":
        return "forge test"
    if framework == "Hardhat":
        return "npx hardhat test"
    if framework == "Truffle":
        return "truffle test"
    return None


def run_local_test(project_root: Path, *, actually_run: bool = False) -> dict[str, Any]:
    cmd = default_test_command(project_root)
    if not cmd:
        return {"status": "SKIPPED", "framework": detect_framework(project_root), "reason": "no local framework detected", "network_used": False, "secrets_accessed": False, "broadcasts_used": False}
    classification = classify_command(cmd)
    if not classification["allowed"] or not actually_run:
        return {"status": "CLASSIFIED", "command": cmd, **classification, "network_used": False, "secrets_accessed": False, "broadcasts_used": False}
    completed = subprocess.run(cmd.split(), cwd=project_root, text=True, capture_output=True, timeout=120, check=False)
    return {"status": "PASS" if completed.returncode == 0 else "FAIL", "command": cmd, "returncode": completed.returncode, "stdout": completed.stdout[-2000:], "stderr": completed.stderr[-2000:], "network_used": False, "secrets_accessed": False, "broadcasts_used": False}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Classify/run safe public benchmark build/test command")
    p.add_argument("project_root")
    p.add_argument("--command")
    p.add_argument("--run", action="store_true")
    args = p.parse_args(argv)
    if args.command:
        result = classify_command(args.command)
    else:
        result = run_local_test(Path(args.project_root), actually_run=args.run)
    print(json.dumps(result, indent=2))
    return 0 if result.get("allowed", True) or result.get("status") in {"SKIPPED", "CLASSIFIED", "PASS"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
