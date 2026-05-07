#!/usr/bin/env python3
"""Generate attack stories from x-ray signals without calling them findings."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
from pathlib import Path
from typing import Any

from attack_surface_ranker import rank_attack_surface
from asset_flow_analyzer import analyze_asset_flows
from contract_role_graph import build_role_graph
from cross_contract_flow_analyzer import analyze_cross_contract_flows
from lifecycle_inference import infer_lifecycle
from protocol_architecture_mapper import map_architecture
from real_repo_indexer import index_real_repo


def stable_id(prefix: str, *parts: Any) -> str:
    return prefix + "-" + hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:12]


def function_lookup(index: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(str(fn.get("contract") or ""), str(fn.get("name") or "")): fn for fn in index.get("functions", [])}


def role_lookup(role_graph: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(str(row.get("contract") or ""), str(row.get("function") or "")): row for row in role_graph.get("function_permissions", [])}


def bug_template(fn: dict[str, Any], ranked: dict[str, Any], perm: dict[str, Any] | None, cross: dict[str, Any]) -> tuple[str, str, str]:
    reasons = " ".join(ranked.get("reasons") or []).lower()
    body = str(fn.get("body") or "")
    name = str(fn.get("name") or "")
    if "upgrade_or_initializer" in reasons or re.search(r"initialize|upgrade|reinitialize", name + body, re.I):
        return ("proxy-initialization-or-upgrade", "unauthorized-privileged-action", "attacker seizes or changes privileged upgrade/initialization state")
    if perm and perm.get("unguarded_sensitive"):
        return ("access-control", "unauthorized-privileged-action", "attacker reaches a sensitive state-changing path without the sibling guard expected by the role model")
    if "signature_authorization" in reasons:
        return ("signature-replay-or-domain", "stolen-funds", "attacker reuses or recontextualizes an off-chain authorization if nonce, deadline, signer, or domain boundaries are incomplete")
    if "proof_verification" in reasons:
        return ("proof-validation", "stolen-funds", "attacker supplies malformed proof material if dynamic proof, root, leaf, or replay validation is incomplete")
    if "oracle_or_price" in reasons:
        return ("oracle-manipulation", "bad-debt", "attacker manipulates or races a price input before a value-moving action")
    if cross.get("ordering_risk"):
        return ("reentrancy-or-stale-accounting", "stolen-funds", "attacker uses a callback or external callee behavior before accounting is finalized")
    if "token_transfer" in reasons or "native_asset_transfer" in reasons or "accounting_signal" in reasons:
        return ("accounting-desync", "stolen-funds", "attacker enters or exits through a path where recorded accounting and actual balances diverge")
    return ("business-logic", "requires-validation", "attacker exercises this entry point under boundary conditions; concrete impact must be proven before reporting")


def cross_lookup(cross: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for risk in cross.get("ordering_risks", []):
        rows[(str(risk.get("contract") or ""), str(risk.get("function") or ""))] = {"ordering_risk": risk}
    return rows


def generate_attack_stories(
    index: dict[str, Any],
    *,
    architecture: dict[str, Any] | None = None,
    role_graph: dict[str, Any] | None = None,
    asset_flows: dict[str, Any] | None = None,
    cross_flows: dict[str, Any] | None = None,
    lifecycle: dict[str, Any] | None = None,
    ranked_surface: dict[str, Any] | None = None,
    max_stories: int = 40,
) -> dict[str, Any]:
    architecture = architecture or map_architecture(index)
    role_graph = role_graph or build_role_graph(index)
    asset_flows = asset_flows or analyze_asset_flows(index)
    cross_flows = cross_flows or analyze_cross_contract_flows(index)
    lifecycle = lifecycle or infer_lifecycle(index)
    ranked_surface = ranked_surface or rank_attack_surface(index, role_graph=role_graph, lifecycle=lifecycle)
    fns = function_lookup(index)
    perms = role_lookup(role_graph)
    crosses = cross_lookup(cross_flows)
    flow_contracts = {str(row.get("contract") or "") for row in asset_flows.get("flows", [])}
    crown_contracts = {str(row.get("contract") or "") for row in architecture.get("crown_jewels", [])}
    stories = []
    for entry in ranked_surface.get("ranked_entrypoints", []):
        if int(entry.get("score") or 0) < 5:
            continue
        key = (str(entry.get("contract") or ""), str(entry.get("function") or ""))
        fn = fns.get(key, {})
        bug_class, impact_type, attacker_action = bug_template(fn, entry, perms.get(key), crosses.get(key, {}))
        if impact_type == "requires-validation" and key[0] not in flow_contracts and key[0] not in crown_contracts:
            continue
        reason_text = ", ".join(entry.get("reasons") or ["source signal"])
        story = {
            "story_id": stable_id("STORY", entry.get("file"), key[0], key[1], bug_class),
            "state": "HYPOTHESIS",
            "bug_class": bug_class,
            "impact_type": impact_type,
            "severity": "High" if impact_type in {"stolen-funds", "bad-debt", "unauthorized-privileged-action"} else "Medium",
            "file_path": entry.get("file"),
            "contract": key[0],
            "function": key[1],
            "line": entry.get("line"),
            "score": entry.get("score"),
            "attacker_capability": "normal external caller unless the role graph proves a stronger precondition",
            "hypothesis": f"Because an attacker can reach {key[0]}.{key[1]} and the x-ray shows {reason_text}, {attacker_action}, causing {impact_type} if the cross-file assumptions fail.",
            "exploit_sequence": [
                f"attacker reaches {key[0]}.{key[1]} with normal permissions or documented role preconditions",
                f"attacker triggers the condition suggested by: {reason_text}",
                "compare attacker/victim/protocol balances or security state before and after",
            ],
            "poc_idea": f"Write a Foundry test around {key[0]}.{key[1]} that sets the boundary state, executes the suspected path, and asserts {impact_type} or kills the lead.",
            "kill_condition": "kill if the function is not reachable by a normal attacker, sibling checks prevent the state transition, or no concrete impact assertion can be made",
            "evidence_missing": ["manual source trace", "concrete asset/state assertion", "working PoC/control test"],
            "uncertainty_label": "hypothesis_only_not_a_finding",
            "evidence": [{"type": "attack_surface", "reasons": entry.get("reasons", []), "score": entry.get("score"), "file_path": entry.get("file"), "line": entry.get("line")}],
            "requires_manual_validation": True,
            "needs_poc": True,
            "counts_as_finding": False,
            "report_ready": False,
        }
        stories.append(story)
        if len(stories) >= max_stories:
            break
    return {
        "status": "PASS",
        "artifact_type": "attack_stories_not_findings",
        "repo_id": index.get("repo_id"),
        "story_count": len(stories),
        "stories": stories,
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
        result = generate_attack_stories(index_real_repo(root, repo_id="self"))
        ok = result["story_count"] >= 1 and result["stories"][0]["counts_as_finding"] is False
        return {"status": "PASS" if ok else "FAIL", "result": result}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Generate attack stories from source x-ray signals")
    p.add_argument("project_root", nargs="?")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        result = self_test()
    else:
        if not args.project_root:
            raise SystemExit("project_root required unless --self-test")
        result = generate_attack_stories(index_real_repo(Path(args.project_root)))
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
