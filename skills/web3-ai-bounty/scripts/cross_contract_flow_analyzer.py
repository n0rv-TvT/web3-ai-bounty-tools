#!/usr/bin/env python3
"""Cross-contract flow analyzer for source-only bounty triage."""

from __future__ import annotations

import argparse
import json
import re
import tempfile
from pathlib import Path
from typing import Any

from real_repo_indexer import EXTERNAL_CALL_RE, LOW_LEVEL_RE, TOKEN_TRANSFER_RE, index_real_repo


STATE_WRITE_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])?\s*(?:\+\+|--|[+\-*/]?=)")


def first_pos(pattern: re.Pattern[str], text: str) -> int | None:
    match = pattern.search(text)
    return match.start() if match else None


def first_state_write_pos(text: str) -> int | None:
    for match in STATE_WRITE_RE.finditer(text):
        prefix = text[max(0, match.start() - 32):match.start()]
        if re.search(r"\b(?:u?int\d*|address|bool|bytes\d*|bytes|string)\s+$", prefix):
            continue
        return match.start()
    return None


def extract_edges(index: dict[str, Any]) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for fn in index.get("functions", []):
        body = str(fn.get("body") or "")
        for match in EXTERNAL_CALL_RE.finditer(body):
            target = re.sub(r"\s+", "", match.group(1))[:80]
            method = match.group(2)
            if target in {"require", "assert", "revert", "emit", "this"}:
                continue
            edges.append({
                "from_contract": fn.get("contract"),
                "from_function": fn.get("name"),
                "file": fn.get("file"),
                "line": fn.get("start_line", 1) + body.count("\n", 0, match.start()),
                "target_expression": target,
                "target_method": method,
                "call_kind": "token_or_contract_call" if TOKEN_TRANSFER_RE.search(match.group(0)) else "contract_call",
                "counts_as_finding": False,
            })
        for match in LOW_LEVEL_RE.finditer(body):
            edges.append({
                "from_contract": fn.get("contract"),
                "from_function": fn.get("name"),
                "file": fn.get("file"),
                "line": fn.get("start_line", 1) + body.count("\n", 0, match.start()),
                "target_expression": "dynamic_low_level_target",
                "target_method": match.group(1),
                "call_kind": "low_level_call",
                "counts_as_finding": False,
            })
    return edges


def ordering_risks(index: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    external_re = re.compile(r"(?:\.call\s*(?:\{|\()|\.delegatecall\s*\(|\.transfer\s*\(|\.send\s*\(|\.safeTransfer\s*\(|\.safeTransferFrom\s*\(|\.transferFrom\s*\()")
    for fn in index.get("functions", []):
        body = str(fn.get("body") or "")
        call_pos = first_pos(external_re, body)
        write_pos = first_state_write_pos(body)
        if call_pos is not None and (write_pos is None or call_pos < write_pos):
            rows.append({
                "file": fn.get("file"),
                "contract": fn.get("contract"),
                "function": fn.get("name"),
                "line": fn.get("start_line"),
                "risk_class": "external_interaction_before_state_update",
                "reason": "external interaction appears before the first state write; review reentrancy and stale-accounting assumptions",
                "counts_as_finding": False,
            })
    return rows


def analyze_cross_contract_flows(index: dict[str, Any]) -> dict[str, Any]:
    edges = extract_edges(index)
    risks = ordering_risks(index)
    assumptions = []
    for edge in edges:
        if edge["call_kind"] in {"low_level_call", "contract_call", "token_or_contract_call"}:
            assumptions.append({
                "from_contract": edge["from_contract"],
                "from_function": edge["from_function"],
                "assumption": "callee behavior, callback behavior, and return semantics do not violate caller accounting or authorization assumptions",
                "target_expression": edge["target_expression"],
                "counts_as_finding": False,
            })
    return {
        "status": "PASS",
        "artifact_type": "cross_contract_flow_analysis_not_findings",
        "repo_id": index.get("repo_id"),
        "edges": edges,
        "edge_count": len(edges),
        "ordering_risks": risks,
        "assumptions": assumptions,
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
        (root / "src" / "Flow.sol").write_text("""pragma solidity ^0.8.20; contract Vault { mapping(address=>uint256) bal; function withdraw() external { uint256 a = bal[msg.sender]; (bool ok,) = msg.sender.call{value:a}(""); require(ok); bal[msg.sender]=0; } }""")
        result = analyze_cross_contract_flows(index_real_repo(root, repo_id="self"))
        ok = result["edge_count"] >= 1 and result["ordering_risks"]
        return {"status": "PASS" if ok else "FAIL", "result": result}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Analyze cross-contract calls and assumptions")
    p.add_argument("project_root", nargs="?")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        result = self_test()
    else:
        if not args.project_root:
            raise SystemExit("project_root required unless --self-test")
        result = analyze_cross_contract_flows(index_real_repo(Path(args.project_root)))
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
