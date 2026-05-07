#!/usr/bin/env python3
"""Infer minimal local PoC setup requirements from hypothesis/source facts.

This is a conservative, protocol-agnostic helper. It identifies categories of
state likely needed for a PoC; it must not invent concrete addresses, balances,
or privileged credentials.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT, case_ids_for_split
from repair_to_poc_candidate_selection import candidate_id_for, find_hypothesis_for_candidate


def infer_expected_aligned_state_setup(root: Path = PUBLIC_ROOT, *, split: str = "fresh-v6") -> dict[str, Any]:
    from expected_aligned_repair_common import base_result_flags, load_json, repair_dir, write_json

    story = load_json(repair_dir(root) / "expected_related_attack_story.json", {})
    root_cause = load_json(repair_dir(root) / "expected_related_root_cause_precision.json", {}).get("candidate") or {}
    impact = load_json(repair_dir(root) / "expected_related_asset_impact.json", {})
    if story.get("status") != "PASS":
        result = {"status": "EXPECTED_RELATED_REPAIR_BLOCKED_MISSING_STATE_SETUP", "split": split, "reason": "attack story did not pass", **base_result_flags()}
    else:
        state_setup = {
            "candidate_id": story.get("candidate_id"),
            "case_id": root_cause.get("case_id"),
            "actors": story.get("actors") or ["attacker", "user"],
            "required_roles": ["normal external user unless local source proves an authorized role is required"],
            "required_token_balances": [impact.get("affected_asset") or "token amount touched by the lifecycle"],
            "required_approvals": ["standard user approvals required by the normal lifecycle, if the entrypoint pulls tokens"],
            "required_oracle_state": [],
            "required_time_or_block_state": ["set a boundary amount containing decimal dust"] if "dust" in str(impact.get("impact_condition") or "").lower() else [],
            "required_prior_lifecycle_steps": story.get("preconditions") or [],
            "required_external_dependencies": ["mock or local harness for the cross-chain/OFT send behavior"] if "cross-chain" in str(impact.get("affected_asset") or "").lower() else [],
            "does_not_invent_concrete_values": True,
            "confidence": story.get("sequence_confidence") or "medium",
        }
        blocks = [] if state_setup["actors"] and state_setup["required_prior_lifecycle_steps"] else ["state setup lacks actors or lifecycle preconditions"]
        result = {"status": "PASS" if not blocks else "EXPECTED_RELATED_REPAIR_BLOCKED_MISSING_STATE_SETUP", "split": split, "candidate_id": story.get("candidate_id"), "state_setup": state_setup, "blocks": blocks, **base_result_flags()}
    return write_json(repair_dir(root) / "expected_related_state_setup.json", result)


def text_for(h: dict[str, Any]) -> str:
    return " ".join(
        str(part or "")
        for part in [
            h.get("title"),
            h.get("bug_class"),
            h.get("file_path") or h.get("file"),
            h.get("contract"),
            h.get("function"),
            h.get("exploit_scenario"),
            " ".join(h.get("exploit_sequence") or []),
            json.dumps(h.get("external_evidence") or []),
        ]
    ).lower()


def infer_state_setup(h: dict[str, Any]) -> dict[str, Any]:
    text = text_for(h)
    actors = ["attacker", "honest user or protocol account"]
    required_roles: list[str] = []
    token_balances: list[str] = []
    approvals: list[str] = []
    oracle_state: list[str] = []
    time_block_state: list[str] = []
    prior_lifecycle_steps: list[str] = []
    external_dependencies: list[str] = []

    if any(token in text for token in ["onlyowner", "role", "admin", "keeper", "operator", "guarded_entrypoint"]):
        required_roles.append("identify whether the tested caller is unprivileged or has the documented role")
    if any(token in text for token in ["transfer", "token", "balance", "deposit", "withdraw", "supply", "redeem", "mint", "burn"]):
        token_balances.append("fund attacker/user/protocol with the token or native asset touched by the function")
        approvals.append("grant only the approvals required by the normal user lifecycle")
    if any(token in text for token in ["oracle", "price", "feed", "twap", "snapshot", "chainlink"]):
        oracle_state.append("set initial oracle/snapshot/feed state and then mutate freshness or price boundary")
    if any(token in text for token in ["timestamp", "deadline", "duration", "epoch", "period", "checkpoint", "nonce"]):
        time_block_state.append("set block time/nonce/checkpoint boundary before the action")
    if any(token in text for token in ["deposit", "supply", "mint", "stake"]):
        prior_lifecycle_steps.append("create a baseline position or accounting entry before the exploit action")
    if any(token in text for token in ["withdraw", "redeem", "claim", "collect"]):
        prior_lifecycle_steps.append("create claimable/withdrawable state before the exploit action")
    if any(token in text for token in ["signature", "permit", "session", "nonce", "domain"]):
        actors.append("authorized signer")
        external_dependencies.append("construct a signature/authorization payload with explicit domain, nonce, action, and caller assumptions")
    if any(token in text for token in ["aave", "strategy", "bridge", "router", "pool", "extension"]):
        external_dependencies.append("deploy or mock the external integration used by the lifecycle path")

    confidence = "medium" if (token_balances or oracle_state or prior_lifecycle_steps or external_dependencies) else "low"
    return {
        "hypothesis_id": h.get("id") or h.get("lead_id"),
        "case_id": h.get("case_id"),
        "actors": list(dict.fromkeys(actors)),
        "required_roles": list(dict.fromkeys(required_roles)),
        "required_token_balances": list(dict.fromkeys(token_balances)),
        "required_approvals": list(dict.fromkeys(approvals)),
        "required_oracle_state": list(dict.fromkeys(oracle_state)),
        "required_time_or_block_state": list(dict.fromkeys(time_block_state)),
        "required_prior_lifecycle_steps": list(dict.fromkeys(prior_lifecycle_steps)),
        "required_external_dependencies": list(dict.fromkeys(external_dependencies)),
        "does_not_invent_concrete_values": True,
        "confidence": confidence,
    }


def infer_candidate_state_setup(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation", candidate: str = "") -> dict[str, Any]:
    selected, hypothesis = find_hypothesis_for_candidate(root, split, candidate)
    if not hypothesis:
        result = {
            "status": "REPAIR_BLOCKED_MISSING_STATE_SETUP",
            "split": split,
            "candidate": candidate,
            "reason": "selected repair candidate could not be resolved to a frozen hypothesis",
            "answer_key_access": False,
            "writeup_access": False,
            "network_used": False,
            "secrets_accessed": False,
            "broadcasts_used": False,
            "counts_toward_readiness": False,
        }
    else:
        setup = infer_state_setup(hypothesis)
        hypothesis_id = str(setup.get("hypothesis_id") or hypothesis.get("id") or hypothesis.get("lead_id") or "")
        case_id = str(hypothesis.get("case_id") or (selected or {}).get("case_id") or "")
        candidate_id = str((selected or {}).get("candidate_id") or candidate_id_for(case_id, hypothesis_id))
        required_categories = [
            setup.get("required_roles"),
            setup.get("required_token_balances"),
            setup.get("required_approvals"),
            setup.get("required_oracle_state"),
            setup.get("required_time_or_block_state"),
            setup.get("required_prior_lifecycle_steps"),
            setup.get("required_external_dependencies"),
        ]
        blocked = not any(required_categories)
        result = {
            "status": "REPAIR_BLOCKED_MISSING_STATE_SETUP" if blocked else "PASS",
            "split": split,
            "candidate_id": candidate_id,
            "hypothesis_id": hypothesis_id,
            "case_id": case_id,
            "state_setup": {**setup, "candidate_id": candidate_id},
            "does_not_invent_concrete_values": setup.get("does_not_invent_concrete_values") is True,
            "frozen_artifacts_only": True,
            "answer_key_access": False,
            "writeup_access": False,
            "network_used": False,
            "secrets_accessed": False,
            "broadcasts_used": False,
            "counts_toward_readiness": False,
        }
    out = root / "scoring" / "repair_to_poc_state_setup_inference.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    return result


def run_split(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation") -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for case_id in case_ids_for_split(root, split):
        path = root / "generated_reports" / f"{case_id}_hypotheses.json"
        if not path.exists():
            continue
        payload = json.loads(path.read_text(errors="replace"))
        rows.extend(infer_state_setup(dict(h, case_id=case_id)) for h in payload.get("hypotheses", []))
    result = {
        "status": "PASS" if rows else "BLOCKED",
        "split": split,
        "inference_count": len(rows),
        "inferences": rows,
        "answer_key_access": False,
        "writeup_access": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "counts_toward_readiness": False,
    }
    out = root / "scoring" / "state_setup_inference.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Infer state setup for frozen hypotheses")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="fresh-confirmation")
    p.add_argument("--frozen-only", action="store_true")
    p.add_argument("--candidate", default="", help="repair candidate id or hypothesis id to infer setup for")
    p.add_argument("--selected", action="store_true", help="infer setup for expected-aligned selected candidate")
    args = p.parse_args(argv)
    if args.selected:
        result = infer_expected_aligned_state_setup(Path(args.root), split=args.split)
    else:
        result = infer_candidate_state_setup(Path(args.root), split=args.split, candidate=args.candidate) if args.candidate else run_split(Path(args.root), split=args.split)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"PASS", "BLOCKED", "REPAIR_BLOCKED_MISSING_STATE_SETUP", "EXPECTED_RELATED_REPAIR_BLOCKED_MISSING_STATE_SETUP"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
