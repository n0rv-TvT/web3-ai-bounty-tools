#!/usr/bin/env python3
"""Guard against silently treating empty large-protocol reports as safety evidence."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from public_corpus_importer import PUBLIC_ROOT, ensure_public_corpus
from source_coverage_gate import evaluate_project, find_case_context, split_csv


FRESH_SPLIT = "fresh-holdout"
FRESH_CONFIRMATION_SPLIT = "fresh-confirmation"
FRESH_V6_SPLIT = "fresh-v6"
FRESH_V8_SPLIT = "fresh-v8"
FRESH_SPLITS = {FRESH_SPLIT, FRESH_CONFIRMATION_SPLIT, FRESH_V6_SPLIT, FRESH_V8_SPLIT}


def load_report(eval_root: Path, case_id: str) -> dict[str, Any]:
    path = eval_root / "generated_reports" / f"{case_id}.json"
    if not path.exists():
        return {"findings": [], "report_missing": True}
    return json.loads(path.read_text(errors="replace"))


def evaluate_guard(case_root: Path, eval_root: Path, case_id: str, *, contract_threshold: int = 10) -> dict[str, Any]:
    coverage = evaluate_project(case_root, case_id=case_id)
    report = load_report(eval_root, case_id)
    findings = report.get("findings", [])
    manual_review = False
    if coverage["coverage_status"] in {"FAIL", "LOW_CONFIDENCE"}:
        status = "INVALID_LOW_COVERAGE"
        reason = "; ".join(coverage.get("blocks") or ["source coverage is insufficient for readiness scoring"])
        manual_review = True
    elif not findings and int(coverage.get("hypotheses_count") or 0) > 0:
        status = "TRIAGE_HYPOTHESES_REQUIRE_MANUAL_REVIEW"
        reason = "source x-ray generated hypotheses/manual-review items but no confirmed final findings"
        manual_review = True
    elif coverage["contracts_indexed"] > contract_threshold and not findings:
        status = "ZERO_LEADS_REQUIRES_MANUAL_REVIEW"
        reason = "large repository produced an empty final report"
        manual_review = True
    elif not findings:
        status = "PASS_SMALL_EMPTY_WITH_COVERAGE"
        reason = "small covered fixture had no findings; still not proof of safety"
    else:
        status = "PASS_FINDINGS_PRESENT"
        reason = "final report contains findings"
    return {
        "case_id": case_id,
        "guard_status": status,
        "reason": reason,
        "manual_review_required": manual_review,
        "empty_report_is_safety_evidence": False,
        "finding_count": len(findings),
        "hypotheses_count": coverage.get("hypotheses_count", 0),
        "manual_review_items": coverage.get("manual_review_items", 0),
        "contracts_indexed": coverage["contracts_indexed"],
        "coverage_status": coverage["coverage_status"],
        "coverage_blocks": coverage.get("blocks", []),
        "answer_key_access": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
    }


def evaluate_cases(root: Path, case_ids: list[str]) -> dict[str, Any]:
    ensure_public_corpus(root)
    rows = []
    for case_id in case_ids:
        eval_root, case_root = find_case_context(root, case_id)
        rows.append(evaluate_guard(case_root, eval_root, case_id))
    return {"status": "PASS" if all(r["guard_status"].startswith("PASS") for r in rows) else "REVIEW_REQUIRED", "cases": rows}


def evaluate_split(root: Path, split: str) -> dict[str, Any]:
    if split in FRESH_SPLITS | {"patched-controls"}:
        fresh_root = root / split
        if not fresh_root.exists() or not any(p.is_dir() for p in fresh_root.iterdir()):
            return {"status": "BLOCKED", "fresh_holdout_status": "blocked_pending_approved_sources", "reason": "no approved/imported fresh-holdout cases available", "split": split, "case_count": 0, "answer_key_access": False, "network_used": False, "secrets_accessed": False, "broadcasts_used": False}
        rows = [evaluate_guard(case_root, root, case_root.name) for case_root in sorted(p for p in fresh_root.iterdir() if p.is_dir())]
        return {"status": "PASS" if all(r["guard_status"].startswith("PASS") for r in rows) else "REVIEW_REQUIRED", "split": split, "cases": rows}
    raise SystemExit(f"unsupported split: {split}")


def self_test() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        case_root = root / "holdout" / "small"
        (case_root / "src").mkdir(parents=True)
        (case_root / "src" / "Safe.sol").write_text("pragma solidity ^0.8.20; contract Safe { function ping() external pure returns (uint) { return 1; } }")
        (root / "generated_reports").mkdir()
        (root / "generated_reports" / "small.json").write_text(json.dumps({"findings": []}))
        result = evaluate_guard(case_root, root, "small")
        return {"status": "PASS" if result["guard_status"] == "PASS_SMALL_EMPTY_WITH_COVERAGE" and result["empty_report_is_safety_evidence"] is False else "FAIL", "result": result}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Guard zero-finding real-protocol reports")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--cases", default="")
    p.add_argument("--split", default="")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        result = self_test()
    elif args.split:
        result = evaluate_split(Path(args.root), args.split)
    elif args.cases:
        result = evaluate_cases(Path(args.root), split_csv(args.cases))
    else:
        raise SystemExit("provide --cases or --self-test")
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") in {"PASS", "REVIEW_REQUIRED", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
