#!/usr/bin/env python3
"""Rank public/external functions by bounty-relevant attack surface."""

from __future__ import annotations

import argparse
import json
import re
import tempfile
from pathlib import Path
from typing import Any

from contract_role_graph import build_role_graph
from lifecycle_inference import infer_lifecycle
from real_repo_indexer import index_real_repo


RISK_NAME_RE = re.compile(r"deposit|withdraw|mint|redeem|borrow|repay|liquidat|stake|unstake|claim|harvest|settle|queue|execute|finalize|cancel|bridge|swap|update|set|initialize|upgrade|slash|rescue|sweep", re.I)


def permission_lookup(role_graph: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(str(row.get("contract") or ""), str(row.get("function") or "")): row for row in role_graph.get("function_permissions", [])}


def lifecycle_lookup(lifecycle: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(str(row.get("contract") or ""), str(row.get("function") or "")): row for row in lifecycle.get("lifecycle_functions", [])}


def rank_function(fn: dict[str, Any], permission: dict[str, Any] | None, lifecycle: dict[str, Any] | None) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    if fn.get("visibility") == "external":
        score += 2; reasons.append("external_entrypoint")
    elif fn.get("visibility") in {"public", "public-default"}:
        score += 1; reasons.append("public_entrypoint")
    if fn.get("state_mutating"):
        score += 2; reasons.append("state_mutating")
    if fn.get("payable"):
        score += 2; reasons.append("payable")
    for flag, weight, reason in [
        (fn.get("contains_token_transfer"), 4, "token_transfer"),
        (fn.get("contains_eth_transfer"), 4, "native_asset_transfer"),
        (fn.get("contains_external_call"), 3, "external_call"),
        (fn.get("contains_accounting_signal"), 3, "accounting_signal"),
        (fn.get("contains_loop"), 1, "loop"),
    ]:
        if flag:
            score += weight; reasons.append(reason)
    blob = str(fn.get("name") or "") + " " + str(fn.get("body") or "")[:500]
    for regex, weight, reason in [
        (re.compile(r"oracle|price|latestRoundData|getPrice|slot0", re.I), 3, "oracle_or_price"),
        (re.compile(r"ecrecover|signature|permit|nonce|DOMAIN_SEPARATOR", re.I), 3, "signature_authorization"),
        (re.compile(r"proof|merkle|root|verify", re.I), 3, "proof_verification"),
        (re.compile(r"initialize|reinitialize|upgradeTo|delegatecall|uups", re.I), 4, "upgrade_or_initializer"),
    ]:
        if regex.search(blob):
            score += weight; reasons.append(reason)
    if RISK_NAME_RE.search(str(fn.get("name") or "")):
        score += 2; reasons.append("lifecycle_or_privileged_name")
    if lifecycle:
        score += 2; reasons.append("lifecycle_phase:" + str(lifecycle.get("phase")))
    if permission and permission.get("unguarded_sensitive"):
        score += 2; reasons.append("unguarded_sensitive_entrypoint")
    if permission and permission.get("guarded"):
        reasons.append("guarded_entrypoint")
    return score, sorted(set(reasons))


def rank_attack_surface(index: dict[str, Any], *, role_graph: dict[str, Any] | None = None, lifecycle: dict[str, Any] | None = None, limit: int = 100) -> dict[str, Any]:
    role_graph = role_graph or build_role_graph(index)
    lifecycle = lifecycle or infer_lifecycle(index)
    perms = permission_lookup(role_graph)
    lifes = lifecycle_lookup(lifecycle)
    rows = []
    for fn in index.get("functions", []):
        if fn.get("visibility") not in {"public", "external", "public-default"}:
            continue
        key = (str(fn.get("contract") or ""), str(fn.get("name") or ""))
        score, reasons = rank_function(fn, perms.get(key), lifes.get(key))
        if score <= 2 and not reasons:
            continue
        rows.append({
            "id": fn.get("id"),
            "file": fn.get("file"),
            "contract": fn.get("contract"),
            "function": fn.get("name"),
            "line": fn.get("start_line"),
            "visibility": fn.get("visibility"),
            "score": score,
            "reasons": reasons,
            "modifiers": fn.get("modifiers", []),
            "state_mutating": fn.get("state_mutating"),
            "counts_as_finding": False,
        })
    rows.sort(key=lambda r: (-int(r["score"]), str(r["file"]), str(r["contract"]), str(r["function"])))
    return {
        "status": "PASS",
        "artifact_type": "attack_surface_ranking_not_findings",
        "repo_id": index.get("repo_id"),
        "ranked_entrypoints": rows[:limit],
        "ranked_count": len(rows),
        "top_score": rows[0]["score"] if rows else 0,
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
        (root / "src" / "Vault.sol").write_text("""pragma solidity ^0.8.20; contract Vault { mapping(address=>uint256) bal; function deposit() external payable { bal[msg.sender]+=msg.value; } function withdraw() external { uint256 a=bal[msg.sender]; (bool ok,) = msg.sender.call{value:a}(""); require(ok); bal[msg.sender]=0; } }""")
        idx = index_real_repo(root, repo_id="self")
        result = rank_attack_surface(idx)
        ok = result["ranked_entrypoints"] and result["ranked_entrypoints"][0]["function"] == "withdraw"
        return {"status": "PASS" if ok else "FAIL", "result": result}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Rank bounty-relevant entry points")
    p.add_argument("project_root", nargs="?")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        result = self_test()
    else:
        if not args.project_root:
            raise SystemExit("project_root required unless --self-test")
        result = rank_attack_surface(index_real_repo(Path(args.project_root)))
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
