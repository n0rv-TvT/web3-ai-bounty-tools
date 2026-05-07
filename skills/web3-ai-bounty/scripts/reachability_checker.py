#!/usr/bin/env python3
"""Reachability checks for expected-aligned post-hoc PoC execution.

This checker is intentionally local-only. It reads already-imported source files
and generated metadata, never network/RPC/report text, and writes a conservative
reachability artifact for the expected-aligned spent-holdout execution flow.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT


CANDIDATE_ID = "EXPECTED-ALIGNED-contest_4001-M-02-HYP-0eeb32c4b28d"
EXECUTION_DIR_NAME = "fresh_v6_expected_aligned_execution"


def safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_") or "candidate"


def load_json(path: Path, default: dict[str, Any] | None = None) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace")) if path.exists() else (default or {})


def execution_dir(root: Path = PUBLIC_ROOT) -> Path:
    out = root / "scoring" / EXECUTION_DIR_NAME
    out.mkdir(parents=True, exist_ok=True)
    return out


def candidate_selection(root: Path = PUBLIC_ROOT) -> dict[str, Any]:
    return load_json(root / "scoring" / "fresh_v6_expected_aligned_repair" / "expected_related_candidate_selection.json", {})


def selected_candidate(root: Path = PUBLIC_ROOT, candidate_id: str = CANDIDATE_ID) -> dict[str, Any]:
    selection = candidate_selection(root)
    candidate = selection.get("candidate") or {}
    if candidate.get("candidate_id") == candidate_id or candidate.get("id") == candidate_id:
        return candidate
    return candidate if not candidate_id else {}


def function_signature_tail(source_text: str, function_name: str) -> str:
    match = re.search(rf"function\s+{re.escape(function_name)}\s*\([^)]*\)\s*([^{{;]*)", source_text, re.S)
    return re.sub(r"\s+", " ", match.group(1)).strip() if match else ""


def function_exists(source_text: str, function_name: str) -> bool:
    return bool(re.search(rf"function\s+{re.escape(function_name)}\s*\(", source_text))


def required_roles_for_signature(signature_tail: str) -> list[str]:
    roles: list[str] = []
    if "onlyOwner" in signature_tail:
        roles.append("owner")
    for role in re.findall(r"onlyRole\s*\(([^)]+)\)", signature_tail):
        roles.append(f"role:{role.strip()}")
    if "onlyEndpoint" in signature_tail or "OnlyLzEndpoint" in signature_tail:
        roles.append("LayerZero endpoint")
    return list(dict.fromkeys(roles))


def analyze_reachability(candidate: dict[str, Any], source_text: str, *, companion_text: str = "") -> dict[str, Any]:
    function_name = str(candidate.get("function") or "")
    signature_tail = function_signature_tail(source_text, function_name)
    exists = bool(function_name and function_exists(source_text, function_name))
    required_roles = required_roles_for_signature(signature_tail)
    internal_or_private = any(token in signature_tail.split() for token in ["internal", "private"])
    routed_by_lz_receive = bool(function_name and re.search(rf"_lzReceive[\s\S]+{re.escape(function_name)}\s*\(", source_text))
    user_facing_unstake = "function unstake(" in companion_text and "msg.sender" in companion_text and "UnstakeMessage" in companion_text
    blocked_by_access_control = bool(required_roles and not (internal_or_private and routed_by_lz_receive))
    preconditions: list[str] = []
    if "user == address(0)" in source_text or "InvalidZeroAddress" in source_text:
        preconditions.append("non-zero user address")
    if "_origin.srcEid == 0" in source_text:
        preconditions.append("non-zero source endpoint id")
    if "unstakeThroughComposer" in source_text:
        preconditions.append("user has completed cooldown assets available to unstake through the composer")
    if "_send(ASSET_OFT" in source_text:
        preconditions.append("asset OFT send adapter is configured for the return leg")
    if routed_by_lz_receive:
        preconditions.append("authorized LayerZero peer delivers MSG_TYPE_UNSTAKE to _lzReceive")
    if user_facing_unstake:
        preconditions.append("normal user initiates UnstakeMessenger.unstake on the spoke chain")
    entrypoint_reachable = bool(exists and not blocked_by_access_control and (not internal_or_private or routed_by_lz_receive or user_facing_unstake))
    blocks: list[str] = []
    if not exists:
        blocks.append("target function not found in local source")
    if blocked_by_access_control:
        blocks.append("target entrypoint is blocked by a required role")
    if internal_or_private and not routed_by_lz_receive:
        blocks.append("internal/private function lacks a local routing entrypoint")
    confidence = "high" if entrypoint_reachable and routed_by_lz_receive and user_facing_unstake else ("medium" if entrypoint_reachable else "low")
    return {
        "candidate_id": candidate.get("candidate_id") or candidate.get("id"),
        "entrypoint_reachable": entrypoint_reachable,
        "required_roles": required_roles,
        "required_preconditions": list(dict.fromkeys(preconditions)),
        "blocked_by_access_control": blocked_by_access_control,
        "blocked_by_missing_setup": bool(blocks and not blocked_by_access_control),
        "reachability_confidence": confidence,
        "blocks": blocks,
        "target_function_visibility": signature_tail,
        "routed_by_lz_receive": routed_by_lz_receive,
        "normal_user_spoke_unstake_path": user_facing_unstake,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "dependency_install_attempted": False,
        "production_source_modified": False,
        "answer_key_text_dependency": False,
        "counts_toward_readiness": False,
    }


def run(root: Path = PUBLIC_ROOT, *, split: str = "fresh-v6", candidate_id: str = CANDIDATE_ID) -> dict[str, Any]:
    candidate = selected_candidate(root, candidate_id)
    if not candidate:
        result = {
            "candidate_id": candidate_id,
            "entrypoint_reachable": False,
            "required_roles": [],
            "required_preconditions": [],
            "blocked_by_access_control": False,
            "blocked_by_missing_setup": True,
            "reachability_confidence": "low",
            "blocks": ["expected-aligned candidate selection missing"],
            "counts_toward_readiness": False,
        }
    else:
        target = root / split / str(candidate.get("case_id")) / str(candidate.get("file_path") or candidate.get("file") or "")
        source_text = target.read_text(errors="replace") if target.exists() else ""
        companion = root / split / str(candidate.get("case_id")) / "src/token/wiTRY/crosschain/UnstakeMessenger.sol"
        companion_text = companion.read_text(errors="replace") if companion.exists() else ""
        result = analyze_reachability(candidate, source_text, companion_text=companion_text)
        result.update({"case_id": candidate.get("case_id"), "expected_finding_id": candidate.get("expected_finding_id"), "target_file": str(candidate.get("file_path") or candidate.get("file") or "")})
    execution_dir(root).joinpath("expected_aligned_reachability.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check expected-aligned candidate reachability")
    parser.add_argument("--root", default=str(PUBLIC_ROOT))
    parser.add_argument("--split", default="fresh-v6")
    parser.add_argument("--candidate", default=CANDIDATE_ID)
    args = parser.parse_args(argv)
    result = run(Path(args.root), split=args.split, candidate_id=args.candidate)
    print(json.dumps(result, indent=2))
    return 0 if not result.get("blocks") else 1


if __name__ == "__main__":
    raise SystemExit(main())
