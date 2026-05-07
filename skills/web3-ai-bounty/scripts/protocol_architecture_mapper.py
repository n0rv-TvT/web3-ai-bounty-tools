#!/usr/bin/env python3
"""Protocol architecture mapper for source-only bounty triage.

This module consumes ``real_repo_indexer`` output and creates an x-ray style
architecture map. It is intentionally a lead generator: rows are untrusted
signals, not findings.
"""

from __future__ import annotations

import argparse
import json
import re
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from real_repo_indexer import index_real_repo


ROLE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "vault": ("vault", "4626", "deposit", "withdraw", "redeem", "shares", "strategy"),
    "lending": ("market", "borrow", "repay", "liquidat", "debt", "collateral"),
    "oracle": ("oracle", "price", "twap", "rounddata", "pyth", "chainlink"),
    "bridge": ("bridge", "message", "endpoint", "layerzero", "wormhole", "send", "receive"),
    "staking_rewards": ("stake", "unstake", "reward", "gauge", "epoch", "checkpoint"),
    "governance": ("govern", "vote", "proposal", "timelock", "delegate", "policy"),
    "access_controller": ("owner", "admin", "role", "manager", "keeper", "operator", "controller"),
    "token": ("erc20", "erc721", "erc1155", "token", "mint", "burn", "transfer"),
    "router": ("router", "swap", "route", "zap", "multicall"),
    "factory": ("factory", "clone", "create", "deploy"),
    "upgrade_boundary": ("proxy", "upgrade", "initialize", "uups", "beacon"),
    "ai_tool_boundary": ("agent", "tool", "sign", "prompt", "wallet", "intent", "session"),
}

DEPENDENCY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "openzeppelin": ("openzeppelin", "@openzeppelin"),
    "chainlink": ("chainlink", "aggregatorv3"),
    "pyth": ("pyth",),
    "uniswap": ("uniswap", "v2", "v3", "pool"),
    "layerzero": ("layerzero", "lz"),
    "wormhole": ("wormhole",),
    "token_standard": ("erc20", "erc721", "erc1155", "safeerc20"),
    "upgrade_lib": ("proxy", "uups", "upgradeable"),
}


def lower_join(*parts: Any) -> str:
    return " ".join(str(p or "") for p in parts).lower()


def functions_by_contract(index: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for fn in index.get("functions", []):
        grouped[str(fn.get("contract") or "")].append(fn)
    return grouped


def state_by_contract(index: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in index.get("state_variables", []):
        grouped[str(row.get("contract") or "")].append(row)
    return grouped


def import_text(index: dict[str, Any]) -> str:
    return " ".join(str(row.get("import") or "") for row in index.get("imports", []))


def role_scores_for(contract: dict[str, Any], fns: list[dict[str, Any]], states: list[dict[str, Any]], imports: str) -> Counter[str]:
    text = lower_join(
        contract.get("name"),
        " ".join(contract.get("inherits") or []),
        " ".join(fn.get("name") or "" for fn in fns),
        " ".join(fn.get("body") or "" for fn in fns[:30]),
        " ".join(row.get("name") or "" for row in states),
        imports,
    )
    scores: Counter[str] = Counter()
    for role, tokens in ROLE_KEYWORDS.items():
        for token in tokens:
            if token in text:
                scores[role] += 1
    return scores


def classify_dependency(import_body: str) -> str:
    lower = import_body.lower()
    for kind, tokens in DEPENDENCY_KEYWORDS.items():
        if any(token in lower for token in tokens):
            return kind
    if import_body.startswith("@"): 
        return "package"
    if import_body.startswith(".") or import_body.startswith('".'):
        return "local"
    return "external_or_unknown"


def summarize_external_dependencies(index: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for imp in index.get("imports", []):
        body = str(imp.get("import") or "")
        rows.append({"file": imp.get("file"), "line": imp.get("line"), "import": body, "dependency_kind": classify_dependency(body)})
    return rows


def crown_jewel_reason(contract: str, fns: list[dict[str, Any]], states: list[dict[str, Any]]) -> list[str]:
    reasons: list[str] = []
    if any(fn.get("contains_token_transfer") or fn.get("contains_eth_transfer") for fn in fns):
        reasons.append("asset_movement")
    if any(fn.get("contains_accounting_signal") for fn in fns) or any(re.search(r"share|asset|debt|collateral|reward|balance|reserve", str(s.get("name") or ""), re.I) for s in states):
        reasons.append("accounting_state")
    if any(fn.get("contains_external_call") for fn in fns):
        reasons.append("external_call_boundary")
    if any(re.search(r"oracle|price|rate", fn.get("name", ""), re.I) for fn in fns):
        reasons.append("oracle_or_price_path")
    if any(re.search(r"initialize|upgrade|admin|owner|role", fn.get("name", "") + " " + " ".join(fn.get("modifiers") or []), re.I) for fn in fns):
        reasons.append("privileged_or_upgrade_path")
    if re.search(r"vault|market|bridge|staking|router|controller|oracle", contract, re.I):
        reasons.append("name_indicates_core_component")
    return sorted(set(reasons))


def map_architecture(index: dict[str, Any]) -> dict[str, Any]:
    fns = functions_by_contract(index)
    states = state_by_contract(index)
    imports = import_text(index)
    contracts = list(index.get("contracts", [])) + list(index.get("interfaces", [])) + list(index.get("libraries", []))
    role_rows = []
    crown_jewels = []
    protocol_types: Counter[str] = Counter()
    for contract in contracts:
        name = str(contract.get("name") or "")
        scores = role_scores_for(contract, fns.get(name, []), states.get(name, []), imports)
        primary = scores.most_common(1)[0][0] if scores else "core_or_unknown"
        protocol_types[primary] += 1
        reasons = crown_jewel_reason(name, fns.get(name, []), states.get(name, []))
        row = {
            "file": contract.get("file"),
            "contract": name,
            "kind": contract.get("kind"),
            "inherits": contract.get("inherits", []),
            "primary_role": primary,
            "role_scores": dict(scores),
            "confidence": "HIGH" if scores and scores.most_common(1)[0][1] >= 3 else ("MEDIUM" if scores else "LOW"),
            "function_count": len(fns.get(name, [])),
            "state_variable_count": len(states.get(name, [])),
            "crown_jewel_reasons": reasons,
            "counts_as_finding": False,
        }
        role_rows.append(row)
        if reasons:
            crown_jewels.append({k: row[k] for k in ["file", "contract", "primary_role", "crown_jewel_reasons", "function_count"]})
    dependencies = summarize_external_dependencies(index)
    return {
        "status": "PASS",
        "artifact_type": "architecture_map_not_findings",
        "repo_id": index.get("repo_id"),
        "contract_count": len(index.get("contracts", [])),
        "interface_count": len(index.get("interfaces", [])),
        "library_count": len(index.get("libraries", [])),
        "roles": sorted(role_rows, key=lambda r: (str(r["file"]), str(r["contract"]))),
        "protocol_types": [role for role, _count in protocol_types.most_common()],
        "crown_jewels": crown_jewels,
        "external_dependencies": dependencies,
        "dependency_kinds": dict(Counter(row["dependency_kind"] for row in dependencies)),
        "ai_boundary_signals": index.get("prompt_injection_hits", []),
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
        (root / "src" / "Vault.sol").write_text("""
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
contract Vault { mapping(address=>uint256) public shares; function deposit(address token,uint256 amount) external { IERC20(token).transferFrom(msg.sender,address(this),amount); shares[msg.sender]+=amount; } function withdraw(address token,uint256 amount) external { shares[msg.sender]-=amount; IERC20(token).transfer(msg.sender,amount); } }
interface IERC20 { function transferFrom(address,address,uint256) external returns(bool); function transfer(address,uint256) external returns(bool); }
""")
        idx = index_real_repo(root, repo_id="self")
        result = map_architecture(idx)
        ok = result["crown_jewels"] and any(row["primary_role"] == "vault" for row in result["roles"])
        return {"status": "PASS" if ok else "FAIL", "result": result}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Map source-only Web3 protocol architecture")
    p.add_argument("project_root", nargs="?")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        result = self_test()
    else:
        if not args.project_root:
            raise SystemExit("project_root required unless --self-test")
        result = map_architecture(index_real_repo(Path(args.project_root)))
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
