#!/usr/bin/env python3
"""Bounty-focused source-only protocol x-ray orchestrator."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from asset_flow_analyzer import analyze_asset_flows
from attack_story_generator import generate_attack_stories
from attack_surface_ranker import rank_attack_surface
from bounty_hypothesis_engine import generate_bounty_hypotheses
from contract_role_graph import build_role_graph
from cross_contract_flow_analyzer import analyze_cross_contract_flows
from lifecycle_inference import infer_lifecycle
from manual_review_queue import build_manual_review_queue
from poc_idea_generator import generate_poc_ideas
from protocol_architecture_mapper import map_architecture
from real_repo_indexer import index_real_repo


def run_protocol_xray(project_root: Path, *, repo_id: str | None = None, include_tests: bool = False, max_hypotheses: int = 40) -> dict[str, Any]:
    index = index_real_repo(project_root, repo_id=repo_id, include_tests=include_tests)
    architecture = map_architecture(index)
    role_graph = build_role_graph(index)
    asset_flows = analyze_asset_flows(index)
    cross_flows = analyze_cross_contract_flows(index)
    lifecycle = infer_lifecycle(index)
    ranked = rank_attack_surface(index, role_graph=role_graph, lifecycle=lifecycle)
    stories = generate_attack_stories(
        index,
        architecture=architecture,
        role_graph=role_graph,
        asset_flows=asset_flows,
        cross_flows=cross_flows,
        lifecycle=lifecycle,
        ranked_surface=ranked,
        max_stories=max_hypotheses,
    )
    hypotheses = generate_bounty_hypotheses(index, stories=stories, max_hypotheses=max_hypotheses)
    poc_ideas = generate_poc_ideas(hypotheses)
    manual_queue = build_manual_review_queue(index, hypotheses=hypotheses, ranked_surface=ranked)
    return {
        "status": "PASS",
        "artifact_type": "protocol_xray_not_vulnerability_report",
        "project_root": str(project_root),
        "repo_id": index.get("repo_id"),
        "include_tests": include_tests,
        "confirmed_findings_statement": "No confirmed findings; x-ray output contains hypotheses and manual-review items only.",
        "counts": {
            "files_indexed": len(index.get("files_indexed", [])),
            "contracts": len(index.get("contracts", [])),
            "interfaces": len(index.get("interfaces", [])),
            "libraries": len(index.get("libraries", [])),
            "functions": len(index.get("functions", [])),
            "risk_signals": len(index.get("risk_signals", [])),
            "ranked_entrypoints": ranked.get("ranked_count", 0),
            "attack_stories": stories.get("story_count", 0),
            "hypotheses": hypotheses.get("hypothesis_count", 0),
            "manual_review_items": manual_queue.get("manual_review_count", 0),
            "working_pocs": poc_ideas.get("working_poc_count", 0),
            "report_ready": hypotheses.get("report_ready_count", 0),
        },
        "index_summary": {k: index.get(k) for k in ["repo_id", "files_indexed", "answer_key_access", "network_used", "secrets_accessed", "broadcasts_used"]},
        "architecture": architecture,
        "role_graph": role_graph,
        "asset_flows": asset_flows,
        "cross_contract_flows": cross_flows,
        "lifecycle": lifecycle,
        "attack_surface": ranked,
        "attack_stories": stories,
        "bounty_hypotheses": hypotheses,
        "poc_ideas": poc_ideas,
        "manual_review_queue": manual_queue,
        "protocol_marked_safe": False,
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
        result = run_protocol_xray(root, repo_id="self")
        ok = result["counts"]["hypotheses"] >= 1 and result["counts"]["report_ready"] == 0 and result["protocol_marked_safe"] is False
        return {"status": "PASS" if ok else "FAIL", "result": result}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run source-only protocol x-ray")
    p.add_argument("project_root", nargs="?")
    p.add_argument("--repo-id", default="")
    p.add_argument("--include-tests", action="store_true")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        result = self_test()
    else:
        if not args.project_root:
            raise SystemExit("project_root required unless --self-test")
        result = run_protocol_xray(Path(args.project_root), repo_id=args.repo_id or None, include_tests=args.include_tests)
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
