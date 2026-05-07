#!/usr/bin/env python3
"""Infer protocol lifecycle paths from Solidity entry points."""

from __future__ import annotations

import argparse
import json
import re
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from real_repo_indexer import index_real_repo


PHASE_PATTERNS: dict[str, tuple[str, ...]] = {
    "deposit": ("deposit", "supply", "fund", "join", "lock"),
    "mint": ("mint",),
    "withdraw": ("withdraw", "exit"),
    "redeem": ("redeem",),
    "borrow": ("borrow", "draw"),
    "repay": ("repay", "payback"),
    "liquidate": ("liquidat", "seize"),
    "stake": ("stake",),
    "unstake": ("unstake", "unbond"),
    "claim": ("claim", "collect", "harvest"),
    "queue": ("queue", "request"),
    "execute": ("execute", "finalize", "complete", "settle"),
    "cancel": ("cancel", "refund"),
    "bridge_send": ("send", "bridge", "outbound"),
    "bridge_receive": ("receive", "lzreceive", "finalize", "inbound"),
    "admin_update": ("set", "update", "configure", "pause", "upgrade", "initialize"),
}

EXPECTED_COUNTERPARTS: dict[str, tuple[str, ...]] = {
    "deposit": ("withdraw", "redeem"),
    "mint": ("withdraw", "redeem"),
    "borrow": ("repay", "liquidate"),
    "stake": ("unstake", "claim"),
    "queue": ("execute", "cancel"),
    "bridge_send": ("bridge_receive", "cancel"),
}


def phase_for(name: str) -> str | None:
    lower = name.lower()
    for phase, tokens in PHASE_PATTERNS.items():
        if any(token in lower for token in tokens):
            return phase
    return None


def infer_lifecycle(index: dict[str, Any]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    by_contract: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for fn in index.get("functions", []):
        if fn.get("visibility") not in {"public", "external", "public-default"}:
            continue
        phase = phase_for(str(fn.get("name") or ""))
        if not phase:
            continue
        row = {
            "file": fn.get("file"),
            "contract": fn.get("contract"),
            "function": fn.get("name"),
            "phase": phase,
            "visibility": fn.get("visibility"),
            "modifiers": fn.get("modifiers", []),
            "has_asset_movement": bool(fn.get("contains_token_transfer") or fn.get("contains_eth_transfer")),
            "has_accounting_signal": bool(fn.get("contains_accounting_signal")),
            "counts_as_finding": False,
        }
        rows.append(row)
        by_contract[str(fn.get("contract") or "")].append(row)

    phase_counts = dict(Counter(row["phase"] for row in rows))
    sibling_groups = []
    incomplete_paths = []
    for contract, c_rows in by_contract.items():
        phases = sorted({row["phase"] for row in c_rows})
        sibling_groups.append({"contract": contract, "phases": phases, "functions": [{"function": r["function"], "phase": r["phase"]} for r in c_rows], "counts_as_finding": False})
        for phase, counterparts in EXPECTED_COUNTERPARTS.items():
            if phase in phases and not any(counterpart in phases for counterpart in counterparts):
                incomplete_paths.append({
                    "contract": contract,
                    "phase": phase,
                    "missing_counterparts": list(counterparts),
                    "review_reason": "lifecycle phase lacks an obvious counterpart by name; verify docs and cross-contract paths before treating as issue",
                    "counts_as_finding": False,
                })
    return {
        "status": "PASS",
        "artifact_type": "lifecycle_inference_not_findings",
        "repo_id": index.get("repo_id"),
        "lifecycle_functions": rows,
        "phase_counts": phase_counts,
        "sibling_groups": sibling_groups,
        "incomplete_paths": incomplete_paths,
        "counts_as_findings": False,
        "answer_key_access": bool(index.get("answer_key_access")),
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
    }


def self_test() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "src").mkdir()
        (root / "src" / "Market.sol").write_text("""pragma solidity ^0.8.20; contract Market { function deposit() external payable {} function withdraw() external {} function borrow() external {} function liquidate(address user) external {} }""")
        result = infer_lifecycle(index_real_repo(root, repo_id="self"))
        ok = result["phase_counts"].get("deposit") == 1 and result["phase_counts"].get("borrow") == 1
        return {"status": "PASS" if ok else "FAIL", "result": result}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Infer protocol lifecycle functions")
    p.add_argument("project_root", nargs="?")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        result = self_test()
    else:
        if not args.project_root:
            raise SystemExit("project_root required unless --self-test")
        result = infer_lifecycle(index_real_repo(Path(args.project_root)))
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
