#!/usr/bin/env python3
"""Blind Solidity source-to-lead analyzer.

This analyzer intentionally reads source files only (and optional tests when the
caller explicitly enables --include-tests). It never reads expected_findings,
expected_results, README hints, or benchmark metadata.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from evidence_extractor import extract_all_evidence
from prompt_injection_guard import scan_text
from solidity_fixture_indexer import iter_solidity_files, safe_rel


RULE_MAP: dict[str, dict[str, str]] = {
    "external_call_before_state_update": {
        "bug_class": "reentrancy",
        "severity": "Critical",
        "affected_asset": "ETH or native asset held by the vault",
        "impact": "stolen-funds",
        "attacker_capability": "normal depositor with callback-capable receiver",
        "scenario": "attacker reenters withdrawal before balance is cleared and drains other users' liquidity",
    },
    "missing_access_control_on_privileged_asset_transfer": {
        "bug_class": "access-control",
        "severity": "High",
        "affected_asset": "privileged treasury assets",
        "impact": "unauthorized-privileged-action",
        "attacker_capability": "normal external caller",
        "scenario": "attacker calls an unguarded privileged sibling path to transfer treasury assets",
    },
    "cross_function_reentrancy_stale_accounting": {
        "bug_class": "cross-function-reentrancy",
        "severity": "Critical",
        "affected_asset": "vault accounting and reward liquidity",
        "impact": "stolen-funds",
        "attacker_capability": "normal depositor with callback-capable receiver",
        "scenario": "attacker reenters a sibling function while account state remains stale and extracts value before the exit path clears accounting",
    },
    "borrow_uses_public_mutable_oracle_price": {
        "bug_class": "oracle-manipulation",
        "severity": "Critical",
        "affected_asset": "borrowed debt token liquidity",
        "impact": "bad-debt",
        "attacker_capability": "normal borrower able to influence public price source",
        "scenario": "attacker inflates oracle price, borrows against overstated collateral, and leaves bad debt after price normalization",
    },
    "erc4626_first_depositor_donation_inflation": {
        "bug_class": "erc4626-inflation",
        "severity": "Critical",
        "affected_asset": "vault underlying asset",
        "impact": "stolen-funds",
        "attacker_capability": "first depositor able to donate assets directly",
        "scenario": "first depositor donates assets to inflate share price so a later depositor mints zero shares",
    },
    "reward_pool_current_balance_accounting": {
        "bug_class": "reward-accounting-desync",
        "severity": "High",
        "affected_asset": "reward token pool",
        "impact": "stolen-funds",
        "attacker_capability": "normal staker entering after rewards are funded",
        "scenario": "late staker joins after rewards are funded and claims rewards earned before their stake existed",
    },
    "initializer_without_guard": {
        "bug_class": "proxy-initialization",
        "severity": "Critical",
        "affected_asset": "owner-controlled protocol assets",
        "impact": "unauthorized-privileged-action",
        "attacker_capability": "normal external caller",
        "scenario": "attacker calls unguarded initializer to become owner and reach owner-only privileged actions",
    },
    "unprotected_selfdestruct": {
        "bug_class": "access-control",
        "severity": "Critical",
        "affected_asset": "contract ETH balance and contract liveness",
        "impact": "stolen-funds",
        "attacker_capability": "normal external caller",
        "scenario": "attacker calls an unprotected destruct function and redirects the contract ETH balance while destroying the contract",
    },
    "public_owner_assignment_without_guard": {
        "bug_class": "access-control",
        "severity": "High",
        "affected_asset": "owner-controlled protocol assets",
        "impact": "unauthorized-privileged-action",
        "attacker_capability": "normal external caller",
        "scenario": "attacker calls an unguarded owner assignment path to seize privileged control over protected assets",
    },
    "signature_without_nonce_domain_deadline": {
        "bug_class": "signature-replay",
        "severity": "Critical",
        "affected_asset": "escrowed signed-withdrawal assets",
        "impact": "stolen-funds",
        "attacker_capability": "holder of one valid signature",
        "scenario": "attacker reuses the same valid signature because authorization lacks nonce/domain/deadline consumption",
    },
    "credits_requested_amount_not_balance_delta": {
        "bug_class": "nonstandard-token-accounting",
        "severity": "High",
        "affected_asset": "vault token liquidity",
        "impact": "stolen-funds",
        "attacker_capability": "normal depositor using a supported nonstandard token",
        "scenario": "attacker deposits a token that transfers less than requested while the vault credits the full requested amount",
    },
    "consumed_message_set_after_external_interaction": {
        "bug_class": "cross-chain-double-finalize",
        "severity": "Critical",
        "affected_asset": "bridge escrow liquidity",
        "impact": "stolen-funds",
        "attacker_capability": "message receiver with callback behavior",
        "scenario": "attacker reenters message finalization before the message is marked consumed and receives the release twice",
    },
    "decimal_normalization_mismatch": {
        "bug_class": "decimal-normalization",
        "severity": "High",
        "affected_asset": "borrowed liquidity or priced asset reserves",
        "impact": "bad-debt",
        "attacker_capability": "normal user supplying low-decimal collateral",
        "scenario": "attacker exploits missing decimal normalization so collateral is overvalued and excess debt is issued",
    },
    "unchecked_arithmetic_pre_solidity_08": {
        "bug_class": "arithmetic-overflow",
        "severity": "High",
        "affected_asset": "token balances or accounting state",
        "impact": "stolen-funds",
        "attacker_capability": "normal caller able to choose arithmetic input values",
        "scenario": "attacker uses unchecked pre-0.8 arithmetic overflow or underflow to corrupt balances and extract value",
    },
    "miner_controlled_randomness": {
        "bug_class": "bad-randomness",
        "severity": "Medium",
        "affected_asset": "lottery or wagered ETH prize pool",
        "impact": "stolen-funds",
        "attacker_capability": "normal participant or miner-influenced transaction sender",
        "scenario": "attacker predicts or influences block-derived randomness to win a payout from the prize pool",
    },
    "unchecked_low_level_call_return": {
        "bug_class": "unchecked-low-level-call",
        "severity": "Medium",
        "affected_asset": "ETH or token transfer outcome",
        "impact": "frozen-funds",
        "attacker_capability": "normal caller interacting with a failing callee or receiver",
        "scenario": "attacker or failing callee causes a low-level call to fail while the contract continues as if the transfer succeeded",
    },
    "missing_dynamic_proof_length_validation": {
        "bug_class": "invalid-validation",
        "severity": "High",
        "affected_asset": "assets or rights released after proof verification",
        "impact": "stolen-funds",
        "attacker_capability": "normal prover able to supply proof bytes and root/leaf fields",
        "scenario": "attacker mutates a proof field that lacks a length check so an empty or incomplete proof is accepted and replay or release guards are bypassed",
    },
    "skip_branch_does_not_advance_loop_index": {
        "bug_class": "loop-logic",
        "severity": "High",
        "affected_asset": "assets or security action controlled by skipped external components",
        "impact": "frozen-funds-or-slashing-bypass",
        "attacker_capability": "normal user able to create state containing a component that later must be skipped",
        "scenario": "attacker places an item in a skip-list path where the skipped branch does not advance the primary loop index, causing the skipped item to be processed anyway",
    },
    "temporary_accounting_debit_not_considered_in_slash": {
        "bug_class": "accounting-desync",
        "severity": "Medium",
        "affected_asset": "temporarily debited shares or slashable economic exposure",
        "impact": "slashing-bypass",
        "attacker_capability": "normal participant whose exposure can be temporarily debited before a penalty event",
        "scenario": "attacker reaches a lifecycle where slashable exposure is temporarily removed from current shares during the penalty calculation and later credited back",
    },
    "all_or_nothing_external_component_withdrawal": {
        "bug_class": "incomplete-withdrawal-path",
        "severity": "Medium",
        "affected_asset": "pending withdrawal assets or shares",
        "impact": "frozen-funds",
        "attacker_capability": "normal user able to include or interact with a reverting external component",
        "scenario": "attacker or failing component causes an all-or-nothing withdrawal finalization loop to revert because no skip, cancel, or partial-completion path exists",
    },
}


def stable_lead_id(ev: dict[str, Any]) -> str:
    raw = json.dumps({k: ev.get(k) for k in ["file_path", "contract", "function", "rule", "line_start"]}, sort_keys=True)
    return "BLIND-" + hashlib.sha256(raw.encode()).hexdigest()[:12]


def evidence_to_lead(ev: dict[str, Any]) -> dict[str, Any]:
    spec = RULE_MAP.get(ev["rule"], {})
    confidence = 0.86 if spec.get("severity") == "Critical" else 0.78
    return {
        "lead_id": stable_lead_id(ev),
        "source": "blind_source_analyzer",
        "state": "MANUAL_LEAD" if confidence >= 0.75 else "HYPOTHESIS",
        "bug_class": spec.get("bug_class", ev["rule"]),
        "file_path": ev["file_path"],
        "contract": ev["contract"],
        "function": ev["function"],
        "code_path": f"{ev['file_path']}:{ev['line_start']}-{ev['line_end']}::{ev['contract']}.{ev['function']}",
        "attacker_capability": spec.get("attacker_capability", "normal external caller"),
        "affected_asset": spec.get("affected_asset", "protocol asset"),
        "exploit_scenario": spec.get("scenario", "source pattern indicates possible exploit path requiring PoC"),
        "impact": spec.get("impact", "concrete impact requires validation"),
        "likelihood": "High" if confidence >= 0.8 else "Medium",
        "severity": spec.get("severity", "Medium"),
        "confidence": confidence,
        "evidence": [ev],
        "needs_poc": True,
    }


def prompt_injection_log(project_root: Path, *, include_tests: bool = False) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for path in iter_solidity_files(project_root, include_tests=include_tests, include_safe_config=False):
        rel = safe_rel(path, project_root)
        scan = scan_text(path.read_text(errors="replace"), source=rel)
        hits.extend(scan.get("hits", []))
    return hits


def analyze_project(project_root: Path, *, include_tests: bool = False) -> dict[str, Any]:
    evidence_result = extract_all_evidence(project_root, include_tests=include_tests)
    leads = [evidence_to_lead(ev) for ev in evidence_result["evidence"]]
    return {
        "mode": "blind_source_analysis",
        "project_root": str(project_root),
        "include_tests": include_tests,
        "read_files": evidence_result["read_files"],
        "answer_key_read": any("expected_findings" in f or "expected_results" in f for f in evidence_result["read_files"]),
        "prompt_injection_hits": prompt_injection_log(project_root, include_tests=include_tests),
        "lead_count": len(leads),
        "leads": leads,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Blindly analyze Solidity source and emit candidate leads")
    p.add_argument("project_root")
    p.add_argument("--include-tests", action="store_true")
    args = p.parse_args(argv)
    print(json.dumps(analyze_project(Path(args.project_root), include_tests=args.include_tests), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
