#!/usr/bin/env python3
"""Generate non-executing regression test plans for Proof-of-Patch pairs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT, load_case_outputs
from patch_diff_analyzer import analyze_split as analyze_patch_diff

PRIORITY_FUNCTIONS = ["deposit", "mint", "withdraw", "redeem", "requestDeposit", "requestRedeem", "processDeposit", "processMint", "collectDeposit", "collectRedeem", "multicall", "transfer", "permit"]
PRECISION_REGENERATION_DIR = "precision_regeneration"


def load_manifest(root: Path) -> dict[str, Any]:
    path = root / "patched_control_manifest.json"
    return json.loads(path.read_text(errors="replace")) if path.exists() else {"pairs": []}


def load_metadata(root: Path, pair: dict[str, Any]) -> dict[str, Any]:
    path = root / pair.get("metadata_path", "")
    return json.loads(path.read_text(errors="replace")) if path.exists() else {}


def precision_dir(root: Path) -> Path:
    out = root / "scoring" / PRECISION_REGENERATION_DIR
    out.mkdir(parents=True, exist_ok=True)
    return out


def regenerated_hypothesis_count(root: Path, pair_id: str) -> int:
    total = 0
    for version_kind in ["vulnerable", "patched"]:
        path = precision_dir(root) / f"{pair_id}_{version_kind}_regenerated_hypotheses.json"
        if path.exists():
            total += len(json.loads(path.read_text(errors="replace")).get("hypotheses", []))
    return total


def require_frozen(root: Path, pair: dict[str, Any]) -> list[str]:
    blocks = []
    for key in ["vulnerable_case_id", "patched_case_id"]:
        if load_case_outputs(root, pair[key])["status"] != "PASS":
            blocks.append(f"{pair[key]} frozen outputs missing")
    return blocks


def plan_for_pair(root: Path, pair: dict[str, Any], diff: dict[str, Any], *, regenerated: bool = False) -> dict[str, Any]:
    blocks = require_frozen(root, pair)
    if blocks:
        return {"pair_id": pair.get("pair_id"), "status": "BLOCKED", "blocks": blocks, "does_not_execute_untrusted_tests": True}
    metadata = load_metadata(root, pair)
    changed_functions = diff.get("changed_functions") or []
    target_function = next((fn for fn in PRIORITY_FUNCTIONS if fn in changed_functions), changed_functions[0] if changed_functions else str(metadata.get("main_contract") or "targetFunction").split("/")[-1].replace(".sol", ""))
    attack_steps = [
        "deploy identical vulnerable and patched test fixtures with the same initial state",
        f"execute the original suspected {metadata.get('expected_vulnerability', 'bug')} path against {target_function}",
        "record attacker, victim, and protocol balances/accounting before and after",
    ]
    return {
        "pair_id": pair["pair_id"],
        "status": "PASS",
        "test_plan": {
            "vulnerable_test": {
                "goal": "prove the vulnerable version permits the original behavior before any report-ready claim",
                "setup": ["instantiate vulnerable source", "fund attacker/victim/protocol actors", "set baseline accounting or access-control state"],
                "attack_steps": attack_steps,
                "assertion": "assert attacker profit, unauthorized state change, frozen funds, bad debt, or exact invariant violation",
            },
            "patched_test": {
                "goal": "prove the patched version blocks the same attack sequence",
                "same_attack_steps": attack_steps,
                "expected_result": "revert | no_profit | no_state_change | accounting_preserved",
                "assertion": "assert the vulnerable assertion no longer holds and honest behavior remains available",
            },
        },
        "required_mocks": ["malicious caller/token/oracle only if required by the hypothesis"],
        "limitations": ["plan only; no untrusted tests executed", "does not promote any hypothesis to REPORT_READY"],
        "metadata_used_after_freeze_only": True,
        "post_hoc_regression_only": bool(regenerated),
        "regenerated_hypothesis_count": regenerated_hypothesis_count(root, pair["pair_id"]) if regenerated else 0,
        "does_not_execute_untrusted_tests": True,
        "report_ready_created": False,
        "counts_as_finding": False,
    }


def plan_split(root: Path = PUBLIC_ROOT, *, split: str = "patched-controls", regenerated: bool = False) -> dict[str, Any]:
    manifest = load_manifest(root)
    diff = analyze_patch_diff(root, split=split)
    diff_by_pair = {row["pair_id"]: row for row in diff.get("pairs", [])}
    rows = [plan_for_pair(root, pair, diff_by_pair.get(pair["pair_id"], {}), regenerated=regenerated) for pair in manifest.get("pairs", [])]
    result = {
        "status": "PASS" if rows and all(r["status"] == "PASS" for r in rows) else "BLOCKED",
        "split": split,
        "classification": "post_hoc_regression_only" if regenerated else "post_freeze_patch_regression_plan",
        "pair_count": len(rows),
        "patch_regression_test_plan_count": sum(1 for r in rows if r.get("status") == "PASS"),
        "does_not_execute_untrusted_tests": True,
        "metadata_used_after_freeze_only": True,
        "production_readiness_changed": False,
        "pairs": rows,
    }
    out = precision_dir(root) / "regenerated_patch_regression_test_plan.json" if regenerated else root / "scoring" / "patch_regression_test_plan.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Plan vulnerable-vs-patched regression tests without executing them")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="patched-controls")
    p.add_argument("--frozen-only", action="store_true")
    p.add_argument("--regenerated", action="store_true", help="write post-hoc regenerated patch-regression plan")
    args = p.parse_args(argv)
    result = plan_split(Path(args.root), split=args.split, regenerated=args.regenerated)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
