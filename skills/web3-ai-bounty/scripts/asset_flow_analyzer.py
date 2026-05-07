#!/usr/bin/env python3
"""Asset-flow analyzer for source-only Web3 bounty triage."""

from __future__ import annotations

import argparse
import json
import re
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from real_repo_indexer import index_real_repo


INBOUND_RE = re.compile(r"deposit|mint|stake|repay|fund|lock|supply|join|add", re.I)
OUTBOUND_RE = re.compile(r"withdraw|redeem|claim|borrow|liquidat|refund|sweep|rescue|release|exit|unstake|send", re.I)
ACCOUNTING_WRITE_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])?)\s*(?:\+\+|--|[+\-*/]?=)")
BALANCE_DELTA_RE = re.compile(r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)", re.I)


def function_lookup(index: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(str(fn.get("contract") or ""), str(fn.get("name") or "")): fn for fn in index.get("functions", [])}


def direction_for(fn: dict[str, Any], occurrence: dict[str, Any]) -> str:
    name = str(fn.get("name") or "")
    body = str(fn.get("body") or "")
    text = str(occurrence.get("text") or "") + " " + body[:250]
    if INBOUND_RE.search(name) or "transferFrom(msg.sender" in text.replace(" ", ""):
        return "inbound"
    if OUTBOUND_RE.search(name) or re.search(r"transfer\s*\(\s*msg\.sender|safeTransfer\s*\(\s*msg\.sender", text):
        return "outbound"
    if "transferFrom" in text:
        return "inbound_or_delegated"
    return "unknown"


def state_writes(fn: dict[str, Any]) -> list[str]:
    names = []
    body = str(fn.get("body") or "")
    for match in ACCOUNTING_WRITE_RE.finditer(body):
        prefix = body[max(0, match.start() - 32):match.start()]
        if re.search(r"\b(?:u?int\d*|address|bool|bytes\d*|bytes|string)\s+$", prefix):
            continue
        name = match.group(1).split("[")[0]
        if name not in {"uint", "uint256", "int", "bool", "address", "i", "j", "ok"}:
            names.append(name)
    return sorted(set(names))


def accounting_states(index: dict[str, Any], contract: str) -> list[dict[str, Any]]:
    rows = []
    for state in index.get("state_variables", []):
        if state.get("contract") != contract:
            continue
        blob = str(state.get("name") or "") + " " + str(state.get("type") or "")
        if re.search(r"\bbal\b|balance|share|asset|debt|collateral|reward|reserve|liquidity|total|queue|index", blob, re.I):
            rows.append(state)
    return rows


def analyze_asset_flows(index: dict[str, Any]) -> dict[str, Any]:
    lookup = function_lookup(index)
    flows: list[dict[str, Any]] = []
    for kind, asset_type, rows in [
        ("token_transfer", "erc20_or_token", index.get("token_transfers", [])),
        ("eth_transfer", "native_asset", index.get("eth_transfers", [])),
    ]:
        for occ in rows:
            fn = lookup.get((str(occ.get("contract") or ""), str(occ.get("function") or "")), {})
            direction = direction_for(fn, occ)
            writes = state_writes(fn)
            flows.append({
                "id": occ.get("id"),
                "kind": kind,
                "asset_type": asset_type,
                "direction": direction,
                "file": occ.get("file"),
                "contract": occ.get("contract"),
                "function": occ.get("function"),
                "line": occ.get("line"),
                "text": occ.get("text"),
                "accounting_state_writes": writes,
                "accounting_state_candidates": [s.get("name") for s in accounting_states(index, str(occ.get("contract") or ""))],
                "counts_as_finding": False,
            })

    by_contract: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for flow in flows:
        by_contract[str(flow.get("contract") or "")].append(flow)

    invariants = []
    risk_candidates = []
    for contract, rows in by_contract.items():
        directions = {row["direction"] for row in rows}
        states = [s.get("name") for s in accounting_states(index, contract)]
        if states and rows:
            invariants.append({
                "contract": contract,
                "invariant": "recorded accounting state should stay synchronized with actual token/native-asset balances across all value-moving paths",
                "state_variables": states,
                "flow_count": len(rows),
                "counts_as_finding": False,
            })
        if "inbound" in directions and "outbound" in directions and states:
            risk_candidates.append({
                "contract": contract,
                "risk_class": "accounting_desync",
                "reason": "contract has both inbound and outbound asset flows plus accounting state",
                "functions": sorted({row["function"] for row in rows}),
                "counts_as_finding": False,
            })

    for fn in index.get("functions", []):
        body = str(fn.get("body") or "")
        if fn.get("contains_token_transfer") and "transferFrom" in body and "+= amount" in body and not BALANCE_DELTA_RE.search(body):
            risk_candidates.append({
                "contract": fn.get("contract"),
                "function": fn.get("name"),
                "risk_class": "requested_amount_credit_without_balance_delta",
                "reason": "deposit-like token flow appears to credit requested amount; review fee-on-transfer/rebasing token assumptions",
                "counts_as_finding": False,
            })

    return {
        "status": "PASS",
        "artifact_type": "asset_flow_analysis_not_findings",
        "repo_id": index.get("repo_id"),
        "flows": flows,
        "flow_count": len(flows),
        "invariants": invariants,
        "risk_candidates": risk_candidates,
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
        (root / "src" / "Vault.sol").write_text("""pragma solidity ^0.8.20; contract Vault { mapping(address=>uint256) public shares; function deposit(address token,uint256 amount) external { IERC20(token).transferFrom(msg.sender,address(this),amount); shares[msg.sender]+=amount; } function withdraw(address token,uint256 amount) external { shares[msg.sender]-=amount; IERC20(token).transfer(msg.sender,amount); } } interface IERC20 { function transferFrom(address,address,uint256) external returns(bool); function transfer(address,uint256) external returns(bool); }""")
        result = analyze_asset_flows(index_real_repo(root, repo_id="self"))
        ok = result["flow_count"] >= 2 and result["invariants"] and result["risk_candidates"]
        return {"status": "PASS" if ok else "FAIL", "result": result}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Analyze source-only asset flows")
    p.add_argument("project_root", nargs="?")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        result = self_test()
    else:
        if not args.project_root:
            raise SystemExit("project_root required unless --self-test")
        result = analyze_asset_flows(index_real_repo(Path(args.project_root)))
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
