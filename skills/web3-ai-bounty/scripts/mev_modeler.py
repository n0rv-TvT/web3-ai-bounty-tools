#!/usr/bin/env python3
"""Practical evidence gate for MEV/order-dependent Web3 leads."""

from __future__ import annotations

import argparse
import json
import re
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any


SEVERITY = ["Critical", "High", "Medium", "Low", "Informational"]


def dec(value: Any) -> Decimal:
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return Decimal("0")


def add_block(blocks: list[dict[str, str]], rule: str, reason: str) -> None:
    blocks.append({"rule": rule, "reason": reason})


def evaluate_mev_lead(lead: dict[str, Any]) -> dict[str, Any]:
    blocks: list[dict[str, str]] = []
    sequence = lead.get("ordered_transaction_sequence") or lead.get("ordered_sequence") or []
    severity = str(lead.get("severity") or "").title()
    profit = dec(lead.get("profit_estimate_usd") or lead.get("profit_loss_estimate") or 0)
    protocol_loss = dec(lead.get("protocol_loss_usd") or 0)
    if len(sequence) < 2:
        add_block(blocks, "missing_ordered_sequence", "MEV lead requires explicit ordered transaction sequence")
    for field in ["attacker_capability", "victim_action", "preconditions", "mitigations", "severity_rationale"]:
        if not lead.get(field):
            add_block(blocks, f"missing_{field}", f"MEV lead missing {field}")
    if severity in {"High", "Critical"} and profit <= 0 and protocol_loss <= 0:
        add_block(blocks, "missing_profit_for_high_severity", "High/Critical MEV severity requires realistic profit or protocol loss")
    if lead.get("missing_slippage") and profit <= 0 and protocol_loss <= 0 and severity in {"High", "Critical"}:
        add_block(blocks, "missing_slippage_not_high", "missing slippage alone is not automatically High")
    claim = str(lead.get("claim") or lead.get("description") or "")
    if re.search(r"\b(could|might|may|possibly|potentially)\b", claim, re.I) and not sequence:
        add_block(blocks, "speculative_mev_claim", "speculative MEV claim lacks ordered evidence")
    if "oracle" in str(lead.get("bug_class") or "").lower() and not lead.get("mev_specific"):
        add_block(blocks, "not_mev", "normal oracle/economic attack must be separated from MEV")
    return {"status": "MEV_PASS" if not blocks else "MEV_BLOCK", "blocks": blocks, "block_count": len(blocks), "profit_estimate_usd": str(profit), "protocol_loss_usd": str(protocol_loss)}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Evaluate MEV lead evidence")
    p.add_argument("lead_json")
    args = p.parse_args(argv)
    print(json.dumps(evaluate_mev_lead(json.loads(Path(args.lead_json).read_text(errors="replace"))), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
