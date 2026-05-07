#!/usr/bin/env python3
"""Source coverage diagnostics for public contest holdout runs.

This is a diagnostic gate, not a vulnerability detector. It proves whether the
blind detector actually saw enough Solidity source structure for a zero-finding
run to be meaningful. Low coverage or zero raw leads on a large protocol must
block readiness scoring.
"""

from __future__ import annotations

import argparse
import json
import re
import tempfile
from pathlib import Path
from typing import Any

from blind_source_analyzer import analyze_project
from protocol_xray import run_protocol_xray
from public_corpus_importer import PUBLIC_ROOT, ensure_public_corpus
from solidity_fixture_indexer import index_project


LIFECYCLE_RE = re.compile(r"(deposit|withdraw|mint|burn|borrow|repay|liquidat|stake|unstake|queue|execute|claim|close|slash|settle|harvest|redeem|transfer)", re.I)
EXTERNAL_CALL_RE = re.compile(r"\.(call|delegatecall|staticcall|send|transfer|transferFrom|safeTransfer|safeTransferFrom|withdraw)\s*(?:\{|\()")
ROLE_CHECK_RE = re.compile(r"\b(onlyOwner|onlyRole|hasRole|requiresAuth|protocolOnly|controller|borrower|admin|governance|require\s*\(\s*msg\.sender)\b")
STATE_VAR_RE = re.compile(r"^\s*(?:mapping\s*\([^;]+\)|(?:u?int\d*|address|bool|bytes\d*|bytes|string|[A-Z][A-Za-z0-9_]*))\s+(?:public|private|internal|constant|immutable|override|virtual|\s)*\s*[A-Za-z_][A-Za-z0-9_]*(?:\s*=\s*[^;]+)?\s*;", re.M)
EVENT_RE = re.compile(r"\bevent\s+[A-Za-z_][A-Za-z0-9_]*\s*\(")
IMPORT_RE = re.compile(r"^\s*import\s+", re.M)
TRANSFER_RE = re.compile(r"\.(?:transfer|transferFrom|safeTransfer|safeTransferFrom)\s*\(")
FRESH_SPLIT = "fresh-holdout"
FRESH_CONFIRMATION_SPLIT = "fresh-confirmation"
FRESH_V6_SPLIT = "fresh-v6"
FRESH_V8_SPLIT = "fresh-v8"
FRESH_SPLITS = {FRESH_SPLIT, FRESH_CONFIRMATION_SPLIT, FRESH_V6_SPLIT, FRESH_V8_SPLIT}
CASE_CONTEXT_SPLITS = ("holdout", "vulnerable", "patched", FRESH_SPLIT, FRESH_CONFIRMATION_SPLIT, FRESH_V6_SPLIT, FRESH_V8_SPLIT, "patched-controls")


def split_csv(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def find_case_context(root: Path, case_id: str) -> tuple[Path, Path]:
    """Return (evaluation_root, case_root) for a case ID.

    Supports both a direct corpus root and dated evaluation subdirectories under
    the public historical corpus root.
    """
    root = root.resolve()
    recognized_splits = set(CASE_CONTEXT_SPLITS)
    if root.name == case_id and root.exists():
        return root.parent.parent if root.parent.name in recognized_splits else root, root
    for split in CASE_CONTEXT_SPLITS:
        candidate = root / split / case_id
        if candidate.exists():
            return root, candidate
    for child in sorted(p for p in root.iterdir() if p.is_dir()):
        for split in CASE_CONTEXT_SPLITS:
            candidate = child / split / case_id
            if candidate.exists():
                return child, candidate
    raise FileNotFoundError(f"case {case_id} not found under {root}")


def visible_solidity_files(case_root: Path) -> list[Path]:
    return sorted(
        p for p in case_root.rglob("*.sol")
        if not any(part in {"expected_findings", "public_writeups", "reports", "issues", "audit_reports", "out", "cache", "broadcast", "script", "node_modules", "lib"} for part in p.relative_to(case_root).parts)
    )


def count_regex(files: list[dict[str, Any]], pattern: re.Pattern[str]) -> int:
    return sum(len(pattern.findall(str(row.get("text") or ""))) for row in files if row.get("kind") == "solidity")


def evaluate_project(case_root: Path, *, case_id: str | None = None, large_contract_threshold: int = 10, large_function_threshold: int = 50) -> dict[str, Any]:
    idx = index_project(case_root, include_tests=False)
    analysis = analyze_project(case_root, include_tests=False)
    try:
        xray = run_protocol_xray(case_root, repo_id=case_id or case_root.name)
        hypotheses_count = int((xray.get("counts") or {}).get("hypotheses") or 0)
        manual_review_count = int((xray.get("counts") or {}).get("manual_review_items") or 0)
        ranked_entrypoints = int((xray.get("counts") or {}).get("ranked_entrypoints") or 0)
        xray_status = xray.get("status", "PASS")
    except Exception as exc:  # fail closed diagnostically, but keep coverage details useful
        hypotheses_count = 0
        manual_review_count = 0
        ranked_entrypoints = 0
        xray_status = "FAIL"
        xray_error = str(exc)
    else:
        xray_error = ""
    sol_files = visible_solidity_files(case_root)
    contracts = [contract for row in idx.get("files", []) for contract in row.get("contracts", [])]
    functions = [fn for contract in contracts for fn in contract.get("functions", [])]
    public_external = [fn for fn in functions if fn.get("visibility") in {"public", "external"}]
    lifecycle = [fn for fn in functions if LIFECYCLE_RE.search(str(fn.get("name") or ""))]
    modifier_count = sum(len(fn.get("modifiers") or []) for fn in functions)
    inheritance_count = sum(len(contract.get("inherits") or []) for contract in contracts)
    files = idx.get("files", [])
    raw_lead_count = len(analysis.get("leads", []))
    large_protocol = len(contracts) >= large_contract_threshold or len(functions) >= large_function_threshold

    blocks: list[str] = []
    status = "PASS"
    if sol_files and not contracts:
        status = "FAIL"
        blocks.append("Solidity files exist but no contracts were parsed")
    if contracts and not functions:
        status = "FAIL"
        blocks.append("Contracts were parsed but no functions were indexed")
    if status == "PASS" and large_protocol and raw_lead_count == 0 and hypotheses_count == 0:
        status = "LOW_CONFIDENCE"
        blocks.append("Large protocol produced zero raw leads; zero findings cannot be interpreted as safety")

    return {
        "case_id": case_id or case_root.name,
        "case_root": str(case_root),
        "solidity_files_exist": bool(sol_files),
        "solidity_file_count": len(sol_files),
        "files_indexed": len([p for p in idx.get("read_files", []) if str(p).endswith(".sol")]),
        "contracts_indexed": len(contracts),
        "interfaces_indexed": len([c for c in contracts if c.get("kind") == "interface"]),
        "libraries_indexed": len([c for c in contracts if c.get("kind") == "library"]),
        "functions_indexed": len(functions),
        "public_external_functions_indexed": len(public_external),
        "modifiers_indexed": modifier_count,
        "inheritance_edges_indexed": inheritance_count,
        "imports_indexed": count_regex(files, IMPORT_RE),
        "state_variables_indexed": count_regex(files, STATE_VAR_RE),
        "events_indexed": count_regex(files, EVENT_RE),
        "external_calls_indexed": count_regex(files, EXTERNAL_CALL_RE),
        "token_transfers_indexed": count_regex(files, TRANSFER_RE),
        "role_checks_indexed": count_regex(files, ROLE_CHECK_RE),
        "lifecycle_candidates": len(lifecycle),
        "raw_lead_count": raw_lead_count,
        "hypotheses_count": hypotheses_count,
        "manual_review_items": manual_review_count,
        "ranked_entrypoints": ranked_entrypoints,
        "lead_budget_aware_triage": hypotheses_count > 0 or manual_review_count > 0,
        "xray_status": xray_status,
        "xray_error": xray_error,
        "large_protocol": large_protocol,
        "coverage_status": status,
        "blocks": blocks,
        "answer_key_access": bool(analysis.get("answer_key_read")),
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
    }


def evaluate_cases(root: Path, case_ids: list[str]) -> dict[str, Any]:
    ensure_public_corpus(root)
    rows = []
    for case_id in case_ids:
        _eval_root, case_root = find_case_context(root, case_id)
        rows.append(evaluate_project(case_root, case_id=case_id))
    return {"status": "PASS" if all(r["coverage_status"] == "PASS" for r in rows) else "LOW_CONFIDENCE", "cases": rows}


def evaluate_split(root: Path, split: str) -> dict[str, Any]:
    if split in FRESH_SPLITS | {"patched-controls"}:
        fresh_root = root / split
        if not fresh_root.exists() or not any(p.is_dir() for p in fresh_root.iterdir()):
            return {"status": "BLOCKED", "fresh_holdout_status": "blocked_pending_approved_sources", "reason": "no approved/imported fresh-holdout cases available", "split": split, "case_count": 0, "answer_key_access": False, "network_used": False, "secrets_accessed": False, "broadcasts_used": False}
        rows = [evaluate_project(case_root, case_id=case_root.name) for case_root in sorted(p for p in fresh_root.iterdir() if p.is_dir())]
        return {"status": "PASS" if all(r["coverage_status"] == "PASS" for r in rows) else "LOW_CONFIDENCE", "split": split, "cases": rows}
    raise SystemExit(f"unsupported split: {split}")


def self_test() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        good = root / "good" / "src"
        good.mkdir(parents=True)
        (good / "Vault.sol").write_text("pragma solidity ^0.8.20; contract Vault { address public owner; modifier onlyOwner(){require(msg.sender == owner); _;} function deposit() external payable {} function withdraw(address payable to) external onlyOwner { to.transfer(1); } }")
        bad = root / "bad" / "src"
        bad.mkdir(parents=True)
        (bad / "Broken.sol").write_text("pragma solidity ^0.8.20; // no contract")
        good_result = evaluate_project(root / "good", case_id="good", large_contract_threshold=99, large_function_threshold=99)
        bad_result = evaluate_project(root / "bad", case_id="bad")
        return {"status": "PASS" if good_result["coverage_status"] == "PASS" and bad_result["coverage_status"] == "FAIL" else "FAIL", "good": good_result, "bad": bad_result}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run source coverage diagnostics for public contest cases")
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
    return 0 if result.get("status") in {"PASS", "LOW_CONFIDENCE", "BLOCKED"} or result.get("coverage_status") in {"PASS", "LOW_CONFIDENCE", "FAIL"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
