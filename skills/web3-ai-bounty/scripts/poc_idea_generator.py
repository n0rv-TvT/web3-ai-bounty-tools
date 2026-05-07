#!/usr/bin/env python3
"""Generate PoC plan ideas for hypotheses without marking them as working PoCs."""

from __future__ import annotations

import argparse
import json
import re
import tempfile
from pathlib import Path
from typing import Any

from bounty_hypothesis_engine import generate_bounty_hypotheses
from real_repo_indexer import index_real_repo


PATTERN_STEPS: dict[str, tuple[str, ...]] = {
    "reentrancy-or-stale-accounting": ("deploy callback-capable attacker", "fund victim liquidity", "enter vulnerable position", "trigger callback before accounting finalizes", "assert attacker gain and victim/protocol loss"),
    "accounting-desync": ("create honest baseline accounting", "exercise alternate lifecycle path", "compare recorded accounting with token balances", "assert profitable or freezing delta"),
    "oracle-manipulation": ("seed market/liquidity", "move oracle input or stale price", "borrow/settle against manipulated price", "assert bad debt or protocol loss"),
    "signature-replay-or-domain": ("construct one valid authorization", "execute it once", "replay in same or wrong context", "assert second unauthorized asset/state movement"),
    "proof-validation": ("build valid control proof", "mutate proof/root/leaf/length", "execute verifier/release path", "assert unauthorized acceptance or replay"),
    "access-control": ("set up privileged and non-privileged actors", "call sensitive path as attacker", "assert unauthorized state or asset movement"),
    "proxy-initialization-or-upgrade": ("deploy proxy/implementation state", "call initializer or upgrade path as attacker", "assert owner/admin/implementation changes"),
}


def plan_for_hypothesis(hyp: dict[str, Any]) -> dict[str, Any]:
    bug_class = str(hyp.get("bug_class") or "business-logic")
    steps = list(PATTERN_STEPS.get(bug_class, ("setup baseline", "execute suspected path", "assert exact invariant violation", "add honest control")))
    safe_name = re.sub(r"[^A-Za-z0-9_]", "_", f"{hyp.get('contract')}_{hyp.get('function')}_{bug_class}")[:80]
    return {
        "poc_id": "POC-IDEA-" + str(hyp.get("id", "unknown"))[-12:],
        "lead_id": hyp.get("id") or hyp.get("lead_id"),
        "status": "SCAFFOLD_IDEA_ONLY",
        "working_poc": False,
        "test_name": f"test_exploit_{safe_name}",
        "suggested_path": f"test/{safe_name}.t.sol",
        "command": f"forge test --match-test test_exploit_{safe_name} -vvvv",
        "setup": ["deploy or fork the affected protocol components", "mint/fund attacker and victim actors", "assign only documented roles needed for the honest baseline"],
        "baseline_assertions": ["honest path preserves accounting and balances before attack"],
        "attack_steps": steps,
        "proof_assertions": ["assert exact attacker gain, victim/protocol loss, bad debt, frozen funds, or unauthorized privileged state change"],
        "control_assertions": ["honest/control path succeeds or patched behavior would block the exploit"],
        "promotion_rule": "do not mark PoC PASS until this scaffold is manually implemented and assertions pass",
        "counts_as_finding": False,
    }


def generate_poc_ideas(hypotheses: dict[str, Any]) -> dict[str, Any]:
    ideas = [plan_for_hypothesis(hyp) for hyp in hypotheses.get("hypotheses", [])]
    return {
        "status": "PASS",
        "artifact_type": "poc_ideas_not_working_pocs",
        "repo_id": hypotheses.get("repo_id"),
        "poc_idea_count": len(ideas),
        "ideas": ideas,
        "working_poc_count": 0,
        "counts_as_findings": False,
        "answer_key_access": bool(hypotheses.get("answer_key_access")),
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
    }


def self_test() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "src").mkdir()
        (root / "src" / "Vault.sol").write_text("""pragma solidity ^0.8.20; contract Vault { mapping(address=>uint256) bal; function withdraw() external { uint256 a=bal[msg.sender]; (bool ok,) = msg.sender.call{value:a}(""); require(ok); bal[msg.sender]=0; } }""")
        hyps = generate_bounty_hypotheses(index_real_repo(root, repo_id="self"))
        result = generate_poc_ideas(hyps)
        ok = result["poc_idea_count"] == hyps["hypothesis_count"] and result["working_poc_count"] == 0
        return {"status": "PASS" if ok else "FAIL", "result": result}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Generate PoC ideas for bounty hypotheses")
    p.add_argument("project_root", nargs="?")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        result = self_test()
    else:
        if not args.project_root:
            raise SystemExit("project_root required unless --self-test")
        result = generate_poc_ideas(generate_bounty_hypotheses(index_real_repo(Path(args.project_root))))
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
