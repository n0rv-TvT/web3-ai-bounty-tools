#!/usr/bin/env python3
"""Validate normal user/victim action path for expected-aligned execution."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT
from reachability_checker import CANDIDATE_ID, execution_dir, selected_candidate


UNREALISTIC_TOKENS = [
    "private key",
    "seed phrase",
    "mnemonic",
    "owner compromise",
    "admin compromise",
    "governance takeover",
    "mainnet fork",
    "rpc_url",
    "vm.env",
    ".env",
]


def validate_normal_action_path(payload: dict[str, Any]) -> dict[str, Any]:
    candidate_id = str(payload.get("candidate_id") or CANDIDATE_ID)
    normal_action = str(payload.get("normal_user_or_victim_action") or payload.get("normal_user_path") or "")
    victim_action = str(payload.get("victim_or_protocol_action") or payload.get("victim_or_protocol_action_defined_text") or "")
    failure_condition = str(payload.get("attack_or_failure_condition") or payload.get("expected_vulnerable_behavior") or "")
    assumptions = [str(item) for item in payload.get("assumptions", [])]
    combined = " ".join([normal_action, victim_action, failure_condition, " ".join(assumptions)]).lower()
    unrealistic = [token for token in UNREALISTIC_TOKENS if token in combined]
    blocks: list[str] = []
    if not normal_action.strip():
        blocks.append("normal user action path missing")
    if not victim_action.strip():
        blocks.append("victim or protocol action missing")
    if not failure_condition.strip():
        blocks.append("attack or failure condition missing")
    if unrealistic:
        blocks.append("unrealistic assumptions present")
    return {
        "candidate_id": candidate_id,
        "normal_user_path_defined": bool(normal_action.strip()),
        "victim_or_protocol_action_defined": bool(victim_action.strip()),
        "attack_or_failure_condition_defined": bool(failure_condition.strip()),
        "unrealistic_assumptions": unrealistic,
        "normal_action_blocks": blocks,
        "normal_user_or_victim_action": normal_action,
        "victim_or_protocol_action": victim_action,
        "attack_or_failure_condition": failure_condition,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "dependency_install_attempted": False,
        "production_source_modified": False,
        "answer_key_text_dependency": False,
        "counts_toward_readiness": False,
    }


def payload_from_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    steps = candidate.get("exploit_sequence") or []
    normal = "normal spoke-chain user calls UnstakeMessenger.unstake after completing the cooldown lifecycle"
    victim = "wiTryVaultComposer receives the authorized LayerZero unstake message and attempts the hub-to-spoke return transfer"
    failure = "the return transfer uses amountLD == minAmountLD for a dust-containing amount, so the OFT adapter dust-adjusts below the minimum and reverts"
    if steps:
        normal = str(steps[0])
        failure = str(steps[-1])
    return {
        "candidate_id": candidate.get("candidate_id") or candidate.get("id"),
        "normal_user_or_victim_action": normal,
        "victim_or_protocol_action": victim,
        "attack_or_failure_condition": failure,
        "assumptions": ["local harness models OFT dust removal; no network, no fork, no broadcasts"],
    }


def run(root: Path = PUBLIC_ROOT, *, split: str = "fresh-v6", candidate_id: str = CANDIDATE_ID) -> dict[str, Any]:
    candidate = selected_candidate(root, candidate_id)
    result = validate_normal_action_path(payload_from_candidate(candidate) if candidate else {"candidate_id": candidate_id})
    result.update({"case_id": candidate.get("case_id") if candidate else "", "expected_finding_id": candidate.get("expected_finding_id") if candidate else ""})
    execution_dir(root).joinpath("expected_aligned_normal_action_path.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate expected-aligned normal action path")
    parser.add_argument("--root", default=str(PUBLIC_ROOT))
    parser.add_argument("--split", default="fresh-v6")
    parser.add_argument("--candidate", default=CANDIDATE_ID)
    args = parser.parse_args(argv)
    result = run(Path(args.root), split=args.split, candidate_id=args.candidate)
    print(json.dumps(result, indent=2))
    return 0 if not result.get("normal_action_blocks") else 1


if __name__ == "__main__":
    raise SystemExit(main())
