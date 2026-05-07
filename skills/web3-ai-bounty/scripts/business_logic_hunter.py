#!/usr/bin/env python3
"""Non-scanner business logic hypothesis generator for Web3 lifecycle models."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


LIFECYCLES = ["deposit", "withdraw", "claim", "borrow", "repay", "liquidate", "swap", "stake", "unstake", "upgrade", "oracle_update", "governance_action"]
REVIEW_PASSES = [
    "state_transition_consistency",
    "conservation_of_value",
    "reward_conservation",
    "share_accounting_consistency",
    "permission_consistency",
    "oracle_dependency_consistency",
    "time_epoch_consistency",
    "multi_transaction_abuse",
    "cross_function_interaction",
    "malicious_external_dependency_behavior",
]


def invariant_ideas_for_lifecycle(lifecycle: str) -> list[dict[str, str]]:
    ideas = {
        "deposit": ["credited assets must equal received assets", "shares minted must be proportional", "deposit must not bypass pause/limits"],
        "withdraw": ["withdrawn assets must not exceed owned shares", "accounting decreases with transfer", "last withdraw must not strand funds"],
        "claim": ["claimed rewards cannot exceed accrued rewards", "late users cannot claim prior rewards", "distributed rewards cannot exceed funded rewards"],
        "borrow": ["borrowed debt must remain within collateral limit", "price decimals must normalize", "bad debt cannot be created by price update ordering"],
        "repay": ["repay reduces debt by actual received amount", "overpay refunds correctly", "partial repay updates interest"],
        "liquidate": ["only insolvent accounts liquidatable", "seized collateral matches debt repaid", "liquidation cannot create bad debt"],
        "swap": ["slippage bound respected", "invariant preserved after fees", "recipient receives expected asset"],
        "stake": ["stake checkpoints rewards first", "stake amount equals received amount", "lock state updates"],
        "unstake": ["unstake applies pending rewards/loss", "lock respected", "accounting decremented once"],
        "upgrade": ["initializer cannot be reused", "storage layout preserved", "admin/timelock authorization enforced"],
        "oracle_update": ["price freshness enforced", "sequencer status checked", "fallback cannot weaken trust"],
        "governance_action": ["snapshot prevents flash voting", "timelock delay enforced", "execution authorization checked"],
    }
    return [{"lifecycle": lifecycle, "invariant": item, "asset_meaning": "protects protocol accounting or authorization"} for item in ideas.get(lifecycle, ["state transition preserves intended invariant"])]


def reachable(flow: dict[str, Any]) -> bool:
    return flow.get("reachable", True) is True and flow.get("caller") != "unreachable"


def emit_hypothesis(flow: dict[str, Any], bug_class: str, reason: str) -> dict[str, Any]:
    return {
        "state": "HYPOTHESIS",
        "bug_class": bug_class,
        "lifecycle": flow.get("name") or flow.get("lifecycle"),
        "function": flow.get("function"),
        "reason": reason,
        "evidence_required": ["manual trace", "PoC or invariant", "scope confirmation"],
        "test_idea": f"exercise {flow.get('function') or flow.get('name')} with adversarial ordering and assert invariant",
        "invariant_ideas": invariant_ideas_for_lifecycle(str(flow.get("name") or flow.get("lifecycle") or "unknown")),
    }


def inspect_lifecycle_flow(flow: dict[str, Any]) -> list[dict[str, Any]]:
    if not reachable(flow):
        return []
    out: list[dict[str, Any]] = []
    name = str(flow.get("name") or flow.get("lifecycle") or "")
    if name in {"claim", "stake"} and flow.get("funds_rewards") and not flow.get("checkpoint_before_balance_change", True):
        out.append(emit_hypothesis(flow, "reward-accounting-desync", "reward funding or staking path lacks pre-state checkpoint"))
    if flow.get("missing_state_update") or flow.get("missing_transition_check"):
        out.append(emit_hypothesis(flow, "missing-state-transition-check", "state transition is missing required update/check"))
    if name in {"deposit", "withdraw"} and flow.get("credits_nominal_amount") and not flow.get("uses_balance_delta", False):
        out.append(emit_hypothesis(flow, "token-accounting-desync", "credits nominal amount without balance-delta accounting"))
    if flow.get("external_call") and not flow.get("state_updated_before_external_call", True):
        out.append(emit_hypothesis(flow, "cross-function-interaction", "external call observes stale state or enables callback ordering"))
    if name in {"borrow", "liquidate", "oracle_update"} and flow.get("uses_oracle") and not flow.get("oracle_freshness_check", True):
        out.append(emit_hypothesis(flow, "oracle-dependency-inconsistency", "oracle-dependent lifecycle lacks freshness/consistency check"))
    return out


def analyze_lifecycle_model(model: dict[str, Any]) -> dict[str, Any]:
    hypotheses: list[dict[str, Any]] = []
    invariants: list[dict[str, str]] = []
    for lifecycle in model.get("lifecycles", []):
        flow = lifecycle if isinstance(lifecycle, dict) else {"name": str(lifecycle)}
        hypotheses.extend(inspect_lifecycle_flow(flow))
        invariants.extend(invariant_ideas_for_lifecycle(str(flow.get("name") or flow.get("lifecycle") or "unknown")))
    return {
        "protocol_type": model.get("protocol_type", "unknown"),
        "review_passes": REVIEW_PASSES,
        "hypotheses": hypotheses,
        "invariant_ideas": invariants,
        "classification": "HYPOTHESIS" if hypotheses else "NO_HIGH_SIGNAL_HYPOTHESIS",
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run business-logic lifecycle hypothesis checks")
    p.add_argument("model_json")
    args = p.parse_args(argv)
    print(json.dumps(analyze_lifecycle_model(json.loads(Path(args.model_json).read_text(errors="replace"))), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
