#!/usr/bin/env python3
"""Convert attack stories into bounty hypotheses that cannot be reported yet."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from attack_story_generator import generate_attack_stories, stable_id
from real_repo_indexer import index_real_repo


FINANCIAL_TYPES = {"stolen-funds", "bad-debt", "frozen-funds", "insolvency"}


def confidence_for(score: Any) -> str:
    try:
        value = int(score or 0)
    except (TypeError, ValueError):
        value = 0
    if value >= 12:
        return "MEDIUM"
    if value >= 8:
        return "LOW_MEDIUM"
    return "LOW"


def story_to_hypothesis(story: dict[str, Any]) -> dict[str, Any]:
    impact_type = str(story.get("impact_type") or "requires-validation")
    lead = {
        "id": stable_id("HYP", story.get("story_id")),
        "lead_id": stable_id("HYP", story.get("story_id")),
        "title": f"Hypothesis: {story.get('bug_class')} in {story.get('contract')}.{story.get('function')} needs proof before reporting",
        "state": "HYPOTHESIS",
        "category": "bounty_hypothesis",
        "bug_class": story.get("bug_class"),
        "severity": story.get("severity", "Medium"),
        "file_path": story.get("file_path"),
        "contract": story.get("contract"),
        "function": story.get("function"),
        "code_path": [f"{story.get('file_path')}:{story.get('line')}::{story.get('contract')}.{story.get('function')}"],
        "preconditions": ["source x-ray hypothesis; manual cross-file validation required"],
        "attacker_capabilities": story.get("attacker_capability") or "normal external caller",
        "affected_asset": "protocol-controlled assets or security-sensitive state; exact asset requires validation",
        "exploit_scenario": story.get("hypothesis"),
        "exploit_sequence": story.get("exploit_sequence", []),
        "impact": {"type": impact_type, "asset": "requires validation"},
        "likelihood": "Unknown until manually traced",
        "severity_rationale": "bounty hypothesis generated from source x-ray signals; not a reportable finding",
        "poc": {"path": "", "assertion": False, "idea": story.get("poc_idea", "confirm or kill with a minimal Foundry exploit/control test"), "kill_condition": story.get("kill_condition", "kill if no normal-attacker reachability or no concrete impact")},
        "poc_idea": story.get("poc_idea", "confirm or kill with a minimal Foundry exploit/control test"),
        "kill_condition": story.get("kill_condition", "kill if no normal-attacker reachability or no concrete impact"),
        "evidence_missing": story.get("evidence_missing", ["manual source trace", "working PoC", "economic or privilege impact proof"]),
        "uncertainty_label": story.get("uncertainty_label", "hypothesis_only_not_a_finding"),
        "fix": "do not patch from hypothesis alone; first prove or kill the path with a PoC/control test",
        "confidence": confidence_for(story.get("score")),
        "source": {"origin": "hypothesis", "tool": "bounty_hypothesis_engine"},
        "manual_verified": False,
        "external_evidence": story.get("evidence", []),
        "needs_poc": True,
        "counts_as_finding": False,
        "report_ready": False,
        "promotion_blockers": ["manual_source_trace_required", "working_poc_required", "economic_or_privilege_impact_required", "scope_duplicate_intended_behavior_check_required"],
    }
    if impact_type in FINANCIAL_TYPES:
        lead["financial_impact"] = {
            "currency": "not-quantified",
            "amount": "hypothesis-only; no amount claimed",
            "assumption_source": "source x-ray signal, not economic proof",
            "calculation_method": "requires executable PoC before any report-ready promotion",
        }
    return lead


def generate_bounty_hypotheses(index: dict[str, Any], *, stories: dict[str, Any] | None = None, max_hypotheses: int = 40, **story_kwargs: Any) -> dict[str, Any]:
    stories = stories or generate_attack_stories(index, max_stories=max_hypotheses, **story_kwargs)
    hypotheses = [story_to_hypothesis(story) for story in stories.get("stories", [])[:max_hypotheses]]
    return {
        "status": "PASS",
        "artifact_type": "bounty_hypotheses_not_findings",
        "repo_id": index.get("repo_id"),
        "hypothesis_count": len(hypotheses),
        "hypotheses": hypotheses,
        "report_ready_count": 0,
        "counts_as_findings": False,
        "answer_key_access": bool(index.get("answer_key_access") or stories.get("answer_key_access")),
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
    }


def self_test() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "src").mkdir()
        (root / "src" / "Vault.sol").write_text("""pragma solidity ^0.8.20; contract Vault { mapping(address=>uint256) bal; function deposit() external payable { bal[msg.sender]+=msg.value; } function withdraw() external { uint256 a=bal[msg.sender]; (bool ok,) = msg.sender.call{value:a}(""); require(ok); bal[msg.sender]=0; } }""")
        result = generate_bounty_hypotheses(index_real_repo(root, repo_id="self"))
        ok = result["hypothesis_count"] >= 1 and result["report_ready_count"] == 0 and result["hypotheses"][0]["state"] == "HYPOTHESIS"
        return {"status": "PASS" if ok else "FAIL", "result": result}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Generate bounty hypotheses from source x-ray signals")
    p.add_argument("project_root", nargs="?")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        result = self_test()
    else:
        if not args.project_root:
            raise SystemExit("project_root required unless --self-test")
        result = generate_bounty_hypotheses(index_real_repo(Path(args.project_root)))
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
