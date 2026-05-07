#!/usr/bin/env python3
"""Cross-chain message lifecycle evidence gate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def block(rule: str, reason: str) -> dict[str, str]:
    return {"rule": rule, "reason": reason}


def evaluate_cross_chain_lead(lead: dict[str, Any]) -> dict[str, Any]:
    blocks: list[dict[str, str]] = []
    message_path = lead.get("message_path") or []
    claim = str(lead.get("claim_type") or lead.get("bug_class") or "").lower()
    if not message_path:
        blocks.append(block("missing_message_path", "every cross-chain finding must name exact message path"))
    if "replay" in claim:
        for field in ["message_nonce", "domain_separation", "source_chain_authentication"]:
            if not lead.get(field):
                blocks.append(block(f"missing_{field}", "replay claims require nonce/domain/source-chain evidence"))
    if "double" in claim or "finalize" in claim:
        if not message_path:
            blocks.append(block("double_finalize_missing_path", "double-finalize claim requires message path"))
        if lead.get("double_execution_evidence") is not True:
            blocks.append(block("missing_double_execution_evidence", "double-finalize claim requires double execution evidence"))
    if "finality" in claim and not lead.get("finality_assumption"):
        blocks.append(block("missing_finality_assumption", "finality claim requires chain-specific assumption label"))
    required = ["source_chain_authentication", "destination_chain_authentication", "domain_separation", "message_nonce", "replay_protection", "retry_cancel_logic"]
    missing_required = [field for field in required if lead.get(field) in {None, False, ""}]
    classification = "CROSS_CHAIN_PASS" if not blocks and not missing_required else ("HYPOTHESIS" if missing_required else "CROSS_CHAIN_BLOCK")
    for field in missing_required:
        blocks.append(block(f"missing_{field}", f"cross-chain evidence missing {field}"))
    return {"status": classification, "blocks": blocks, "block_count": len(blocks), "message_path": message_path}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Evaluate cross-chain evidence")
    p.add_argument("lead_json")
    args = p.parse_args(argv)
    print(json.dumps(evaluate_cross_chain_lead(json.loads(Path(args.lead_json).read_text(errors="replace"))), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
