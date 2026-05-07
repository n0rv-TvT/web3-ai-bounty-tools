#!/usr/bin/env python3
"""Run source-only bug bounty triage without producing confirmed findings."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from lead_budget_guard import evaluate_artifact
from protocol_xray import run_protocol_xray
from public_corpus_importer import PUBLIC_ROOT, ensure_public_corpus
from source_coverage_gate import evaluate_project as evaluate_coverage
from source_coverage_gate import find_case_context, split_csv


MODES = {"triage", "spent-regression", "source-only", "source-plus-tests", "precision-regeneration"}
FRESH_SPLIT = "fresh-holdout"
FRESH_CONFIRMATION_SPLIT = "fresh-confirmation"
FRESH_V6_SPLIT = "fresh-v6"
FRESH_V8_SPLIT = "fresh-v8"
FRESH_SPLITS = {FRESH_SPLIT, FRESH_CONFIRMATION_SPLIT, FRESH_V6_SPLIT, FRESH_V8_SPLIT}


def classify_mode(mode: str) -> str:
    if mode == "precision-regeneration":
        return "post_hoc_regression_only"
    return "spent_holdout_posthoc_regression_only" if mode == "spent-regression" else "source_only_bounty_triage"


def blocked_fresh_holdout(mode: str, *, split: str = FRESH_SPLIT) -> dict[str, Any]:
    return {
        "status": "BLOCKED",
        "fresh_holdout_status": "blocked_pending_approved_sources",
        "reason": "no approved fresh holdout source manifest or imported fresh-holdout cases were provided",
        "mode": mode,
        "split": split,
        "case_count": 0,
        "total_hypotheses": 0,
        "total_confirmed_findings": 0,
        "answer_key_access": False,
        "writeup_access": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
    }


def run_project(project_root: Path, *, case_id: str | None = None, mode: str = "triage") -> dict[str, Any]:
    if mode not in MODES:
        raise SystemExit(f"unknown mode: {mode}")
    if mode == "precision-regeneration":
        raise SystemExit("precision-regeneration mode is only supported with --split patched-controls")
    xray = run_protocol_xray(project_root, repo_id=case_id, include_tests=(mode == "source-plus-tests"))
    budget = evaluate_artifact(xray)
    coverage = evaluate_coverage(project_root, case_id=case_id or project_root.name)
    status = "PASS" if budget["status"] in {"PASS", "REVIEW_REQUIRED"} and xray.get("status") == "PASS" else "FAIL"
    return {
        "status": status,
        "case_id": case_id or project_root.name,
        "mode": mode,
        "classification": classify_mode(mode),
        "artifact_type": "bug_bounty_triage_not_vulnerability_report",
        "confirmed_findings_count": 0,
        "report_ready_count": 0,
        "hypothesis_count": xray.get("counts", {}).get("hypotheses", 0),
        "manual_review_count": xray.get("counts", {}).get("manual_review_items", 0),
        "lead_budget": budget,
        "coverage": coverage,
        "xray": xray,
        "protocol_marked_safe": False,
        "counts_as_future_readiness": False if mode == "spent-regression" else "requires_fresh_holdout_policy",
        "answer_key_access": bool(xray.get("answer_key_access") or coverage.get("answer_key_access")),
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
    }


def run_cases(root: Path, case_ids: list[str], *, mode: str = "triage", write: bool = True) -> dict[str, Any]:
    ensure_public_corpus(root)
    rows = []
    for case_id in case_ids:
        eval_root, case_root = find_case_context(root, case_id)
        result = run_project(case_root, case_id=case_id, mode=mode)
        if write:
            out = eval_root / "scoring" / "triage" / f"{case_id}_bug_bounty_triage.json"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(result, indent=2) + "\n")
            result = {**result, "triage_path": out.relative_to(eval_root).as_posix()}
        rows.append(result)
    return {
        "status": "PASS" if all(row["status"] == "PASS" for row in rows) else "FAIL",
        "mode": mode,
        "classification": classify_mode(mode),
        "case_count": len(rows),
        "total_hypotheses": sum(int(row.get("hypothesis_count") or 0) for row in rows),
        "total_confirmed_findings": 0,
        "counts_as_future_readiness": False if mode == "spent-regression" else "requires_fresh_holdout_policy",
        "cases": rows,
    }


def run_split(root: Path, split: str, *, mode: str = "triage") -> dict[str, Any]:
    if mode == "precision-regeneration":
        if split != "patched-controls":
            return {**blocked_fresh_holdout(mode, split=split), "reason": "precision-regeneration is restricted to already-imported patched-controls"}
        from precision_regeneration import regenerate_split

        return regenerate_split(root, split=split)
    if split in FRESH_SPLITS | {"patched-controls"}:
        fresh_root = root / split
        if not fresh_root.exists() or not any(p.is_dir() for p in fresh_root.iterdir()):
            return blocked_fresh_holdout(mode, split=split)
        rows = []
        for case_root in sorted(p for p in fresh_root.iterdir() if p.is_dir()):
            result = run_project(case_root, case_id=case_root.name, mode=mode)
            rows.append(result)
            out_dir = root / "generated_reports"
            out_dir.mkdir(parents=True, exist_ok=True)
            common = {"case_id": case_root.name, "split": split, "mode": mode, "answer_key_loaded": False, "answer_key_read_during_detection": False, "writeup_read_during_detection": False, "network_used": False, "secrets_accessed": False, "broadcasts_used": False}
            artifacts = {
                "confirmed_findings": {**common, "artifact_type": "confirmed_findings", "findings": [], "confirmed_finding_count": 0},
                "hypotheses": {**common, **result["xray"].get("bounty_hypotheses", {})},
                "manual_review_queue": {**common, **result["xray"].get("manual_review_queue", {})},
                "protocol_xray": {**common, **result["xray"]},
                "coverage": {**common, **result["coverage"]},
                "lead_budget": {**common, **result["lead_budget"]},
            }
            for suffix, payload in artifacts.items():
                (out_dir / f"{case_root.name}_{suffix}.json").write_text(json.dumps(payload, indent=2) + "\n")
        return {"status": "PASS" if all(row["status"] == "PASS" for row in rows) else "FAIL", "mode": mode, "split": split, "case_count": len(rows), "total_hypotheses": sum(int(row.get("hypothesis_count") or 0) for row in rows), "total_confirmed_findings": 0, "cases": rows}
    raise SystemExit(f"unsupported split for triage runner: {split}")


def self_test() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "src").mkdir()
        (root / "src" / "Vault.sol").write_text("""pragma solidity ^0.8.20; contract Vault { mapping(address=>uint256) bal; function deposit() external payable { bal[msg.sender]+=msg.value; } function withdraw() external { uint256 a=bal[msg.sender]; (bool ok,) = msg.sender.call{value:a}(""); require(ok); bal[msg.sender]=0; } }""")
        result = run_project(root, case_id="self", mode="spent-regression")
        ok = result["hypothesis_count"] >= 1 and result["confirmed_findings_count"] == 0 and result["counts_as_future_readiness"] is False
        return {"status": "PASS" if ok else "FAIL", "result": result}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run bug bounty triage on local projects or corpus cases")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--cases", default="")
    p.add_argument("--split", default="")
    p.add_argument("--project-root", default="")
    p.add_argument("--case-id", default="")
    p.add_argument("--mode", default="triage", choices=sorted(MODES))
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        result = self_test()
    elif args.project_root:
        result = run_project(Path(args.project_root), case_id=args.case_id or Path(args.project_root).name, mode=args.mode)
    elif args.split:
        result = run_split(Path(args.root), args.split, mode=args.mode)
    elif args.cases:
        result = run_cases(Path(args.root), split_csv(args.cases), mode=args.mode)
    else:
        raise SystemExit("provide --cases, --project-root, or --self-test")
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
