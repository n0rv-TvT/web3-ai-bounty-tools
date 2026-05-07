#!/usr/bin/env python3
"""Non-EVM readiness boundary enforcement."""

from __future__ import annotations

import argparse
import json
from typing import Any


READY = "READY"
LIMITED = "LIMITED"
TRIAGE_ONLY = "TRIAGE_ONLY"
REFUSE_FULL_AUDIT = "REFUSE_FULL_AUDIT"

REQUIREMENTS = {
    "solidity/evm": {"tools": {"forge", "solc"}, "classification_missing": LIMITED},
    "vyper": {"tools": {"vyper"}, "classification_missing": LIMITED},
    "solana/rust": {"tools": {"cargo", "anchor", "solana"}, "classification_missing": REFUSE_FULL_AUDIT},
    "cosmwasm": {"tools": {"cargo", "wasm-opt"}, "classification_missing": REFUSE_FULL_AUDIT},
    "move/sui": {"tools": {"sui"}, "classification_missing": REFUSE_FULL_AUDIT},
    "move/aptos": {"tools": {"aptos"}, "classification_missing": REFUSE_FULL_AUDIT},
    "cairo/starknet": {"tools": {"scarb"}, "classification_missing": REFUSE_FULL_AUDIT},
}


def normalize_ecosystem(ecosystem: str) -> str:
    e = ecosystem.lower().strip()
    aliases = {"evm": "solidity/evm", "solidity": "solidity/evm", "solana": "solana/rust", "sui": "move/sui", "aptos": "move/aptos", "cairo": "cairo/starknet"}
    return aliases.get(e, e)


def evaluate_ecosystem_readiness(ecosystem: str, verified_tools: set[str], verified_playbooks: set[str] | None = None) -> dict[str, Any]:
    key = normalize_ecosystem(ecosystem)
    req = REQUIREMENTS.get(key)
    if not req:
        return {"ecosystem": ecosystem, "classification": TRIAGE_ONLY, "missing_tools": [], "limitations": ["unknown ecosystem"]}
    required = set(req["tools"])
    missing = sorted(required.difference(verified_tools))
    playbooks = verified_playbooks or set()
    if missing:
        classification = req["classification_missing"]
    elif key != "solidity/evm" and key not in playbooks:
        classification = LIMITED
    else:
        classification = READY
    limitations = []
    if missing:
        limitations.append("missing required tools: " + ", ".join(missing))
    if key != "solidity/evm" and key not in playbooks:
        limitations.append("missing verified vulnerability playbook")
    return {"ecosystem": key, "classification": classification, "missing_tools": missing, "limitations": limitations, "may_claim_full_readiness": classification == READY}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Evaluate non-EVM readiness")
    p.add_argument("ecosystem")
    p.add_argument("--tool", action="append", default=[])
    args = p.parse_args(argv)
    print(json.dumps(evaluate_ecosystem_readiness(args.ecosystem, set(args.tool)), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
