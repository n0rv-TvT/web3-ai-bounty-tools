#!/usr/bin/env python3
"""Reusable fuzz and invariant template catalog for Web3 audit harnesses."""

from __future__ import annotations

import argparse
import json
from typing import Any


def template(name: str, purpose: str, invariants: list[str], asset_meaning: str, actions: list[str]) -> dict[str, Any]:
    return {
        "name": name,
        "purpose": purpose,
        "setup": "deploy target, mint assets, configure actors and roles",
        "actors": ["alice", "bob", "attacker", "keeper"],
        "state_variables": ["asset balances", "shares/debt/reward indexes", "total accounting"],
        "allowed_actions": actions,
        "invariants": invariants,
        "asset_meaning": asset_meaning,
        "expected_failure_mode": "invariant violation with concrete asset/accounting delta",
        "false_positive_risks": ["unmodeled admin action", "out-of-scope token behavior", "invalid actor assumption"],
    }


def protocol_templates(protocol_type: str) -> list[dict[str, Any]]:
    p = protocol_type.lower()
    if p in {"vault", "erc4626", "yield"}:
        return [
            template("foundry_invariant_vault_assets", "Ensure redeemable shares remain backed", ["totalAssets >= redeemableAssets", "share price not profitably donation-manipulated", "deposit/withdraw preserves accounting"], "protects vault assets backing user shares", ["deposit", "mint", "withdraw", "redeem", "donate"]),
            template("erc4626_inflation_harness", "Exercise first-deposit and donation inflation", ["victim shares > 0 for meaningful deposit", "attacker profit <= 0 after donation", "preview matches execution bounds"], "prevents theft of depositor assets", ["attackerDeposit", "donate", "victimDeposit", "redeem"]),
            template("malicious_erc20_vault_harness", "Model fee/false-return/rebasing tokens", ["credited <= actually received", "withdrawn <= accounted balance", "fees do not inflate shares"], "protects accounting from non-standard tokens", ["feeTransfer", "falseReturn", "rebase", "deposit"]),
        ]
    if p in {"reward", "staking", "rewards"}:
        return [
            template("reward_conservation_invariant", "Rewards cannot exceed funding", ["claimed + claimable <= funded", "late staker cannot claim prior rewards", "reward index monotonic"], "protects funded reward pool", ["fund", "stake", "unstake", "claim"]),
            template("epoch_transition_harness", "Exercise epoch/checkpoint ordering", ["epoch close assigns rewards once", "unstake applies pending reward/loss", "checkpoint cannot double count"], "prevents reward drift across epochs", ["advanceEpoch", "checkpoint", "stake", "claim"]),
            template("reentrant_reward_receiver", "Callback during reward transfer", ["claim cannot reenter to exceed entitlement", "claimed balance increments before transfer", "pool balance decreases by claimed amount"], "protects reward pool from callback extraction", ["claim", "reenterClaim"]),
        ]
    if p in {"lending", "borrow", "money-market"}:
        return [
            template("lending_solvency_invariant", "Borrow/repay/liquidate remain solvent", ["debt <= collateralValue * LTV", "insolvent accounts cannot withdraw", "liquidation reduces bad debt"], "protects lender liquidity", ["deposit", "borrow", "repay", "liquidate", "withdraw"]),
            template("malicious_oracle_harness", "Exercise stale/manipulated prices", ["stale price cannot create bad debt", "decimal normalization correct", "sequencer-down price blocked"], "prevents oracle-created insolvency", ["setPrice", "borrow", "liquidate"]),
            template("liquidation_edge_fuzz", "Partial liquidation edge cases", ["solvent users not liquidatable", "seize amount <= collateral", "bad debt not increased by liquidation"], "protects borrower collateral and protocol solvency", ["partialRepay", "liquidate", "accrue"]),
        ]
    return [template("generic_foundry_fuzz", "Generic stateful fuzz harness", ["no unauthorized asset gain", "accounting variables remain consistent", "privileged state changes require role"], "protects protocol assets and permissions", ["callExternalFunctions"])]


def generate_template_catalog(protocol_types: list[str]) -> dict[str, Any]:
    return {"schema_version": "1.0.0", "protocols": {p: protocol_templates(p) for p in protocol_types}}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Generate fuzz/invariant templates")
    p.add_argument("protocol", nargs="+")
    args = p.parse_args(argv)
    print(json.dumps(generate_template_catalog(args.protocol), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
