#!/usr/bin/env python3
"""Synthesize concrete PoC assertion targets from generic impact classes.

This module is intentionally protocol-agnostic. It does not know contest names,
report titles, or expected findings. It converts an impact/bug-class hint into
the assertion and kill-condition language required before a hypothesis can be
promoted to a PoC candidate.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT, case_ids_for_split
from repair_to_poc_candidate_selection import candidate_id_for, find_hypothesis_for_candidate
from source_fact_to_attack_story_linker import link_hypothesis


def synthesize_expected_aligned_assertion(root: Path = PUBLIC_ROOT, *, split: str = "fresh-v6") -> dict[str, Any]:
    from expected_aligned_repair_common import base_result_flags, load_json, repair_dir, write_json

    root_cause = load_json(repair_dir(root) / "expected_related_root_cause_precision.json", {}).get("candidate") or {}
    impact = load_json(repair_dir(root) / "expected_related_asset_impact.json", {})
    story = load_json(repair_dir(root) / "expected_related_attack_story.json", {})
    if not root_cause or not impact or story.get("status") != "PASS":
        result = {"status": "EXPECTED_RELATED_REPAIR_BLOCKED_MISSING_ASSERTION", "split": split, "reason": "missing root cause, impact, or attack story", **base_result_flags()}
    else:
        assertion = synthesize_assertion(
            str(impact.get("impact_type") or ""),
            bug_class=str(root_cause.get("bug_class") or ""),
            affected_asset=str(impact.get("affected_asset") or ""),
            contract=str(root_cause.get("contract") or ""),
            function=str(root_cause.get("function") or ""),
        )
        if root_cause.get("source_evidence", [{}])[0].get("pattern") == "min_amount_equals_amount":
            assertion["assertions"] = [
                "assert the dust-containing cross-chain unstake or redeem path reverts when minAmountLD equals the nominal amount",
                "assert the user's normal exit remains unprocessed through this route after the revert",
                "assert a dust-free amount or lowered minimum is the control path that avoids the minimum-amount revert",
            ]
            assertion["kill_condition"] = "kill if the send path dust-adjusts minAmountLD, does not remove dust, or the normal user action succeeds for a dust-containing amount"
        blocks = [] if assertion.get("assertions") and assertion.get("kill_condition") else ["missing assertions or kill condition"]
        result = {
            "status": "PASS" if not blocks else "EXPECTED_RELATED_REPAIR_BLOCKED_MISSING_ASSERTION",
            "split": split,
            "candidate_id": root_cause.get("candidate_id"),
            "assertion_plan": {**assertion, "candidate_id": root_cause.get("candidate_id")},
            "blocks": blocks,
            **base_result_flags(),
        }
    return write_json(repair_dir(root) / "expected_related_assertion_plan.json", result)


def _lower(value: Any) -> str:
    return str(value or "").lower()


def impact_type_for(h: dict[str, Any]) -> str:
    impact = h.get("impact")
    if isinstance(impact, dict):
        return str(impact.get("type") or "")
    return str(h.get("impact_type") or impact or "")


def synthesize_assertion(impact_type: str, *, bug_class: str = "", affected_asset: str = "", contract: str = "", function: str = "") -> dict[str, Any]:
    """Return assertion and kill-condition text for a PoC plan.

    The output is descriptive, not proof. A later executable PoC must implement
    the assertions against concrete balances/state.
    """

    if not any(str(part or "").strip() for part in [impact_type, bug_class, affected_asset, contract, function]):
        return {
            "status": "BLOCKED_MISSING_IMPACT_TYPE",
            "assertion_kind": "missing_impact_type",
            "assertions": [],
            "kill_condition": "",
            "requires_manual_implementation": True,
            "report_ready": False,
            "counts_as_finding": False,
        }

    text = " ".join([impact_type, bug_class, affected_asset, contract, function]).lower()
    asset = affected_asset or "affected asset/state"
    if any(token in text for token in ["frozen", "availability", "denial", "dos", "blocked", "freeze"]):
        kind = "fund_or_function_freeze"
        assertions = [
            f"assert the normal lifecycle action for {asset} reverts or remains unprocessed after the attack",
            "assert the same state cannot be cleared by the normal user action in the tested conditions",
        ]
        kill = "kill if the affected action succeeds normally or a documented user-accessible recovery clears the state"
    elif any(token in text for token in ["stolen", "profit", "drain", "loss", "user-loss", "inflation"]):
        kind = "attacker_profit_or_victim_loss"
        assertions = [
            "assert attacker balance or claimable value increases after the exploit sequence",
            f"assert victim/protocol balance, reserves, or accounting for {asset} decreases or becomes insolvent",
        ]
        kill = "kill if no measurable attacker gain, victim loss, insolvency, or unfair value transfer is observed"
    elif any(token in text for token in ["unauthorized", "privileged", "access", "role"]):
        kind = "unauthorized_privileged_action"
        assertions = [
            "assert a caller without the required role changes privileged state or executes a privileged action",
            "assert the control path with proper authorization is the only expected success path",
        ]
        kill = "kill if authorization, ownership, approval, or signature checks prevent the state transition"
    elif any(token in text for token in ["bad-debt", "debt", "collateral", "oracle", "price", "pricing"]):
        kind = "bad_debt_or_bad_pricing"
        assertions = [
            "assert the manipulated or stale input changes collateral, debt, share, or price output beyond tolerance",
            "assert the incorrect calculation enables undercollateralization, wrong quote, or unfair mint/redeem outcome",
        ]
        kill = "kill if validated oracle bounds, staleness checks, or independent accounting keep the output correct"
    elif any(token in text for token in ["replay", "signature", "nonce", "domain"]):
        kind = "signature_replay_or_auth_bypass"
        assertions = [
            "assert the same signature or authorization payload succeeds in an unintended context or more than once",
            "assert nonce, domain, wallet, chain, or action binding is insufficient for the tested replay",
        ]
        kill = "kill if nonce consumption or domain/action/wallet binding prevents the replayed authorization"
    elif any(token in text for token in ["accounting", "desync", "rounding", "shares", "supply", "assets"]):
        kind = "accounting_invariant_violation"
        assertions = [
            "assert recorded accounting diverges from actual token balances or expected share/debt invariants",
            "assert the divergence changes user/protocol value or blocks a normal lifecycle action",
        ]
        kill = "kill if accounting remains synchronized after the boundary operation and no value/liveness impact occurs"
    else:
        kind = "generic_state_delta"
        assertions = [
            "assert a concrete pre/post state or balance delta tied to accepted bounty impact",
        ]
        kill = "kill if no concrete accepted-impact state or balance delta can be asserted"
    return {
        "assertion_kind": kind,
        "assertions": assertions,
        "kill_condition": kill,
        "requires_manual_implementation": True,
        "report_ready": False,
        "counts_as_finding": False,
    }


def synthesize_for_hypothesis(h: dict[str, Any]) -> dict[str, Any]:
    return {
        "hypothesis_id": h.get("id") or h.get("lead_id"),
        "case_id": h.get("case_id"),
        **synthesize_assertion(
            impact_type_for(h),
            bug_class=str(h.get("bug_class") or ""),
            affected_asset=str(h.get("affected_asset") or ((h.get("impact") or {}).get("asset") if isinstance(h.get("impact"), dict) else "") or ""),
            contract=str(h.get("contract") or ""),
            function=str(h.get("function") or ""),
        ),
    }


def synthesize_candidate_assertion(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation", candidate: str = "") -> dict[str, Any]:
    selected, hypothesis = find_hypothesis_for_candidate(root, split, candidate)
    if not hypothesis:
        result = {
            "status": "REPAIR_BLOCKED_MISSING_ASSERTION",
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
        linked = link_hypothesis(hypothesis)
        enriched_input = {**hypothesis, "affected_asset": linked.get("affected_asset") or hypothesis.get("affected_asset")}
        assertion = synthesize_for_hypothesis(enriched_input)
        hypothesis_id = str(assertion.get("hypothesis_id") or hypothesis.get("id") or hypothesis.get("lead_id") or "")
        case_id = str(hypothesis.get("case_id") or (selected or {}).get("case_id") or "")
        candidate_id = str((selected or {}).get("candidate_id") or candidate_id_for(case_id, hypothesis_id))
        blocked = assertion.get("assertion_kind") == "generic_state_delta" and not assertion.get("assertions")
        result = {
            "status": "REPAIR_BLOCKED_MISSING_ASSERTION" if blocked else "PASS",
            "split": split,
            "candidate_id": candidate_id,
            "hypothesis_id": hypothesis_id,
            "case_id": case_id,
            "source_asset_used": linked.get("affected_asset"),
            "assertion_plan": {**assertion, "candidate_id": candidate_id},
            "frozen_artifacts_only": True,
            "report_ready": False,
            "counts_as_finding": False,
            "answer_key_access": False,
            "writeup_access": False,
            "network_used": False,
            "secrets_accessed": False,
            "broadcasts_used": False,
            "counts_toward_readiness": False,
        }
    out = root / "scoring" / "repair_to_poc_assertion_synthesis.json"
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
        for h in payload.get("hypotheses", []):
            rows.append(synthesize_for_hypothesis(dict(h, case_id=case_id)))
    result = {
        "status": "PASS" if rows else "BLOCKED",
        "split": split,
        "assertion_count": len(rows),
        "assertions": rows,
        "answer_key_access": False,
        "writeup_access": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "counts_toward_readiness": False,
    }
    out = root / "scoring" / "assertion_synthesis.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Synthesize PoC assertion targets from frozen hypotheses")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="fresh-confirmation")
    p.add_argument("--frozen-only", action="store_true")
    p.add_argument("--candidate", default="", help="repair candidate id or hypothesis id to synthesize assertions for")
    p.add_argument("--selected", action="store_true", help="synthesize assertions for expected-aligned selected candidate")
    args = p.parse_args(argv)
    if args.selected:
        result = synthesize_expected_aligned_assertion(Path(args.root), split=args.split)
    else:
        result = synthesize_candidate_assertion(Path(args.root), split=args.split, candidate=args.candidate) if args.candidate else run_split(Path(args.root), split=args.split)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"PASS", "BLOCKED", "REPAIR_BLOCKED_MISSING_ASSERTION", "EXPECTED_RELATED_REPAIR_BLOCKED_MISSING_ASSERTION"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
