#!/usr/bin/env python3
"""Contract role and permission graph for source-only triage."""

from __future__ import annotations

import argparse
import json
import re
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from real_repo_indexer import index_real_repo


ROLE_TOKEN_RE = re.compile(r"\b(owner|admin|governance|governor|keeper|operator|manager|controller|guardian|pauser|borrower|vault|strategy|signer|relayer|executor)\b", re.I)
SENSITIVE_NAME_RE = re.compile(r"(set|update|upgrade|initialize|pause|unpause|sweep|rescue|withdraw|transfer|mint|burn|borrow|liquidat|slash|execute|finalize|claim|harvest|rebalance|bridge)", re.I)
GUARD_TOKEN_RE = re.compile(r"(only[A-Za-z0-9_]+|requiresAuth|auth|hasRole|owner\s*\(|msg\.sender\s*==|_checkRole|whenNotPaused|nonReentrant)", re.I)

SIBLING_FAMILIES: dict[str, tuple[str, ...]] = {
    "deposit_withdraw": ("deposit", "mint", "withdraw", "redeem"),
    "borrow_repay_liquidate": ("borrow", "repay", "liquidat"),
    "stake_unstake_claim": ("stake", "unstake", "claim", "reward"),
    "queue_execute_cancel": ("queue", "execute", "cancel", "finalize", "complete"),
    "create_update_delete": ("create", "set", "update", "delete", "remove"),
    "bridge_send_receive": ("send", "receive", "retry", "refund", "bridge"),
}


def guard_tokens(fn: dict[str, Any]) -> list[str]:
    tokens = set(str(m) for m in fn.get("modifiers", []) if m)
    body = str(fn.get("body") or "")
    for match in GUARD_TOKEN_RE.finditer(body):
        tokens.add(match.group(0).strip())
    return sorted(tokens)


def role_tokens(text: str) -> list[str]:
    return sorted({m.group(1).lower() for m in ROLE_TOKEN_RE.finditer(text or "")})


def is_public_entry(fn: dict[str, Any]) -> bool:
    return fn.get("visibility") in {"public", "external", "public-default"}


def is_sensitive(fn: dict[str, Any]) -> bool:
    blob = " ".join([str(fn.get("name") or ""), str(fn.get("body") or ""), " ".join(fn.get("modifiers") or [])])
    return bool(SENSITIVE_NAME_RE.search(blob) or fn.get("contains_token_transfer") or fn.get("contains_eth_transfer") or fn.get("contains_external_call"))


def family_for(name: str) -> str | None:
    lower = name.lower()
    for family, tokens in SIBLING_FAMILIES.items():
        if any(token in lower for token in tokens):
            return family
    return None


def build_role_graph(index: dict[str, Any]) -> dict[str, Any]:
    contracts = {row.get("name"): row for row in list(index.get("contracts", [])) + list(index.get("interfaces", [])) + list(index.get("libraries", []))}
    state_by_contract: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for state in index.get("state_variables", []):
        state_by_contract[str(state.get("contract") or "")].append(state)

    graph_rows = []
    permission_rows = []
    family_rows: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for contract, meta in contracts.items():
        state_text = " ".join(str(s.get("name") or "") for s in state_by_contract.get(str(contract), []))
        inherits_text = " ".join(meta.get("inherits") or [])
        c_functions = [fn for fn in index.get("functions", []) if fn.get("contract") == contract]
        function_text = " ".join(str(fn.get("name") or "") + " " + str(fn.get("body") or "")[:500] for fn in c_functions)
        roles = role_tokens(" ".join([str(contract), state_text, inherits_text, function_text]))
        graph_rows.append({
            "contract": contract,
            "file": meta.get("file"),
            "inherits": meta.get("inherits", []),
            "role_tokens": roles,
            "state_role_variables": [s.get("name") for s in state_by_contract.get(str(contract), []) if role_tokens(str(s.get("name") or ""))],
            "counts_as_finding": False,
        })
        for fn in c_functions:
            if not is_public_entry(fn):
                continue
            guards = guard_tokens(fn)
            sensitive = is_sensitive(fn)
            row = {
                "file": fn.get("file"),
                "contract": contract,
                "function": fn.get("name"),
                "visibility": fn.get("visibility"),
                "modifiers": fn.get("modifiers", []),
                "guard_tokens": guards,
                "guarded": bool(guards),
                "sensitive": sensitive,
                "unguarded_sensitive": sensitive and not guards,
                "state_mutating": bool(fn.get("state_mutating")),
                "counts_as_finding": False,
            }
            permission_rows.append(row)
            fam = family_for(str(fn.get("name") or ""))
            if fam:
                family_rows[(str(contract), fam)].append(row)

    mismatches = []
    for (contract, family), rows in family_rows.items():
        if len(rows) < 2:
            continue
        guard_sets = {tuple(row["guard_tokens"]) for row in rows if row["sensitive"]}
        if len(guard_sets) > 1 or (any(row["guarded"] for row in rows) and any(not row["guarded"] for row in rows)):
            mismatches.append({
                "contract": contract,
                "family": family,
                "functions": [{"function": r["function"], "guarded": r["guarded"], "guard_tokens": r["guard_tokens"]} for r in rows],
                "review_reason": "sibling lifecycle functions have inconsistent guards; verify intended role model manually",
                "counts_as_finding": False,
            })

    return {
        "status": "PASS",
        "artifact_type": "role_graph_not_findings",
        "repo_id": index.get("repo_id"),
        "contracts": graph_rows,
        "function_permissions": permission_rows,
        "unprotected_sensitive_functions": [row for row in permission_rows if row["unguarded_sensitive"]],
        "sibling_guard_mismatches": mismatches,
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
        (root / "src" / "Roles.sol").write_text("""
pragma solidity ^0.8.20;
contract Vault { address public owner; modifier onlyOwner(){ require(msg.sender == owner); _; } function deposit() external payable {} function withdraw(address payable to) external onlyOwner { to.transfer(1); } function emergencyWithdraw(address payable to) external { to.transfer(1); } }
""")
        result = build_role_graph(index_real_repo(root, repo_id="self"))
        ok = result["unprotected_sensitive_functions"] and result["sibling_guard_mismatches"]
        return {"status": "PASS" if ok else "FAIL", "result": result}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Build contract role/permission graph")
    p.add_argument("project_root", nargs="?")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        result = self_test()
    else:
        if not args.project_root:
            raise SystemExit("project_root required unless --self-test")
        result = build_role_graph(index_real_repo(Path(args.project_root)))
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
