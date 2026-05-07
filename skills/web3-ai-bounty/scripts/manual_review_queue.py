#!/usr/bin/env python3
"""Build a priority manual-review queue from x-ray and hypothesis artifacts."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from attack_surface_ranker import rank_attack_surface
from bounty_hypothesis_engine import generate_bounty_hypotheses
from real_repo_indexer import index_real_repo


def priority_for(score: Any, bug_class: str) -> str:
    try:
        value = int(score or 0)
    except (TypeError, ValueError):
        value = 0
    if bug_class in {"reentrancy-or-stale-accounting", "oracle-manipulation", "signature-replay-or-domain", "access-control", "proxy-initialization-or-upgrade"} or value >= 12:
        return "high"
    if value >= 8:
        return "medium"
    return "low"


def build_manual_review_queue(index: dict[str, Any], *, hypotheses: dict[str, Any] | None = None, ranked_surface: dict[str, Any] | None = None, max_items: int = 50) -> dict[str, Any]:
    hypotheses = hypotheses or generate_bounty_hypotheses(index)
    ranked_surface = ranked_surface or rank_attack_surface(index)
    ranked_by_key = {(row.get("contract"), row.get("function")): row for row in ranked_surface.get("ranked_entrypoints", [])}
    items = []
    for hyp in hypotheses.get("hypotheses", []):
        ranked = ranked_by_key.get((hyp.get("contract"), hyp.get("function")), {})
        items.append({
            "queue_id": "MR-" + str(hyp.get("id", "unknown"))[-12:],
            "lead_id": hyp.get("id"),
            "priority": priority_for(ranked.get("score"), str(hyp.get("bug_class") or "")),
            "file_path": hyp.get("file_path"),
            "contract": hyp.get("contract"),
            "function": hyp.get("function"),
            "bug_class": hyp.get("bug_class"),
            "review_goal": "prove or kill the hypothesis with manual source trace and minimal PoC/control test",
            "questions": [
                "Is this reachable by a normal attacker in the audited version?",
                "Which cross-contract assumption must fail?",
                "What exact asset/state changes and who loses?",
                "Can a minimal PoC assert concrete impact?",
                "Do docs, tests, prior audits, or scope exclusions make this intended or out of scope?",
            ],
            "not_a_finding": True,
            "counts_as_finding": False,
        })
    if not items and ranked_surface.get("ranked_entrypoints"):
        for row in ranked_surface.get("ranked_entrypoints", [])[:10]:
            items.append({
                "queue_id": "MR-SURFACE-" + str(row.get("id", "unknown"))[-8:],
                "lead_id": None,
                "priority": "medium" if int(row.get("score") or 0) >= 8 else "low",
                "file_path": row.get("file"),
                "contract": row.get("contract"),
                "function": row.get("function"),
                "bug_class": "surface-review",
                "review_goal": "ranked surface has no concrete hypothesis yet; inspect manually for missing bug-class context",
                "questions": ["Why did the surface score high?", "Can attacker gain or victim loss be stated?"],
                "not_a_finding": True,
                "counts_as_finding": False,
            })
    order = {"high": 0, "medium": 1, "low": 2}
    items.sort(key=lambda item: (order.get(str(item.get("priority")), 9), str(item.get("file_path")), str(item.get("contract")), str(item.get("function"))))
    return {
        "status": "PASS",
        "artifact_type": "manual_review_queue_not_findings",
        "repo_id": index.get("repo_id"),
        "manual_review_count": len(items[:max_items]),
        "items": items[:max_items],
        "counts_as_findings": False,
        "answer_key_access": bool(index.get("answer_key_access") or hypotheses.get("answer_key_access")),
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
    }


def self_test() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "src").mkdir()
        (root / "src" / "Vault.sol").write_text("""pragma solidity ^0.8.20; contract Vault { mapping(address=>uint256) bal; function withdraw() external { uint256 a=bal[msg.sender]; (bool ok,) = msg.sender.call{value:a}(""); require(ok); bal[msg.sender]=0; } }""")
        result = build_manual_review_queue(index_real_repo(root, repo_id="self"))
        ok = result["manual_review_count"] >= 1 and result["items"][0]["not_a_finding"] is True
        return {"status": "PASS" if ok else "FAIL", "result": result}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Build manual review queue from source x-ray")
    p.add_argument("project_root", nargs="?")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        result = self_test()
    else:
        if not args.project_root:
            raise SystemExit("project_root required unless --self-test")
        result = build_manual_review_queue(index_real_repo(Path(args.project_root)))
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
