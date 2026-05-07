#!/usr/bin/env python3
"""Guard that source-rich protocols produce a useful hypothesis/review budget."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from protocol_xray import run_protocol_xray
from public_corpus_importer import PUBLIC_ROOT, ensure_public_corpus
from source_coverage_gate import find_case_context, split_csv


FRESH_SPLIT = "fresh-holdout"
FRESH_CONFIRMATION_SPLIT = "fresh-confirmation"
FRESH_V6_SPLIT = "fresh-v6"
FRESH_V8_SPLIT = "fresh-v8"
FRESH_SPLITS = {FRESH_SPLIT, FRESH_CONFIRMATION_SPLIT, FRESH_V6_SPLIT, FRESH_V8_SPLIT}


def evaluate_artifact(artifact: dict[str, Any], *, min_hypotheses: int = 3, min_manual_items: int = 1) -> dict[str, Any]:
    counts = artifact.get("counts") or {}
    contract_count = int(counts.get("contracts") or 0) + int(counts.get("interfaces") or 0) + int(counts.get("libraries") or 0)
    function_count = int(counts.get("functions") or 0)
    risk_signal_count = int(counts.get("risk_signals") or 0)
    hypothesis_count = int(counts.get("hypotheses") or 0)
    manual_count = int(counts.get("manual_review_items") or 0)
    ranked_count = int(counts.get("ranked_entrypoints") or 0)
    large_or_source_rich = contract_count >= 10 or function_count >= 50
    source_has_risk = risk_signal_count > 0 or ranked_count > 0
    blocks: list[str] = []
    warnings: list[str] = []
    if large_or_source_rich and source_has_risk and hypothesis_count == 0:
        blocks.append("source-rich protocol with risk signals produced zero hypotheses")
    if source_has_risk and manual_count < min_manual_items:
        blocks.append("risk signals produced no manual-review queue")
    if large_or_source_rich and 0 < hypothesis_count < min_hypotheses:
        warnings.append("large/source-rich protocol produced a very small hypothesis budget")
    if not source_has_risk and function_count > 0:
        warnings.append("no bounty-relevant risk signals found; this is not proof of safety")
    status = "FAIL" if blocks else ("REVIEW_REQUIRED" if warnings else "PASS")
    return {
        "status": status,
        "lead_budget_status": status,
        "blocks": blocks,
        "warnings": warnings,
        "large_or_source_rich": large_or_source_rich,
        "source_has_risk": source_has_risk,
        "hypothesis_count": hypothesis_count,
        "manual_review_count": manual_count,
        "ranked_entrypoint_count": ranked_count,
        "risk_signal_count": risk_signal_count,
        "counts_as_findings": False,
    }


def evaluate_project(project_root: Path, *, case_id: str | None = None) -> dict[str, Any]:
    artifact = run_protocol_xray(project_root, repo_id=case_id)
    return {"case_id": case_id or project_root.name, **evaluate_artifact(artifact), "xray_counts": artifact.get("counts", {})}


def evaluate_cases(root: Path, case_ids: list[str]) -> dict[str, Any]:
    ensure_public_corpus(root)
    rows = []
    for case_id in case_ids:
        _eval_root, case_root = find_case_context(root, case_id)
        rows.append(evaluate_project(case_root, case_id=case_id))
    top = "PASS" if all(row["status"] == "PASS" for row in rows) else ("FAIL" if any(row["status"] == "FAIL" for row in rows) else "REVIEW_REQUIRED")
    return {"status": top, "cases": rows}


def evaluate_split(root: Path, split: str) -> dict[str, Any]:
    if split in FRESH_SPLITS | {"patched-controls"}:
        fresh_root = root / split
        if not fresh_root.exists() or not any(p.is_dir() for p in fresh_root.iterdir()):
            return {"status": "BLOCKED", "fresh_holdout_status": "blocked_pending_approved_sources", "reason": "no approved/imported fresh-holdout cases available", "split": split, "case_count": 0, "answer_key_access": False, "network_used": False, "secrets_accessed": False, "broadcasts_used": False}
        rows = [evaluate_project(case_root, case_id=case_root.name) for case_root in sorted(p for p in fresh_root.iterdir() if p.is_dir())]
        top = "PASS" if all(row["status"] == "PASS" for row in rows) else ("FAIL" if any(row["status"] == "FAIL" for row in rows) else "REVIEW_REQUIRED")
        return {"status": top, "split": split, "cases": rows}
    raise SystemExit(f"unsupported split: {split}")


def self_test() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "src").mkdir()
        for i in range(4):
            (root / "src" / f"Vault{i}.sol").write_text(f"""pragma solidity ^0.8.20; contract Vault{i} {{ mapping(address=>uint256) bal; function deposit() external payable {{ bal[msg.sender]+=msg.value; }} function withdraw() external {{ uint256 a=bal[msg.sender]; (bool ok,) = msg.sender.call{{value:a}}(\"\"); require(ok); bal[msg.sender]=0; }} }}""")
        result = evaluate_project(root, case_id="self")
        ok = result["hypothesis_count"] >= 1 and result["manual_review_count"] >= 1 and result["status"] in {"PASS", "REVIEW_REQUIRED"}
        return {"status": "PASS" if ok else "FAIL", "result": result}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Evaluate bounty hypothesis lead budget")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--cases", default="")
    p.add_argument("--split", default="")
    p.add_argument("--project-root", default="")
    p.add_argument("--case-id", default="")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        result = self_test()
    elif args.project_root:
        result = evaluate_project(Path(args.project_root), case_id=args.case_id or Path(args.project_root).name)
    elif args.split:
        result = evaluate_split(Path(args.root), args.split)
    elif args.cases:
        result = evaluate_cases(Path(args.root), split_csv(args.cases))
    else:
        raise SystemExit("provide --cases, --project-root, or --self-test")
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") in {"PASS", "REVIEW_REQUIRED", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
