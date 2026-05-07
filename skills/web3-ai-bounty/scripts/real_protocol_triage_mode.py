#!/usr/bin/env python3
"""Conservative real-protocol triage artifact generator.

This mode never reports vulnerabilities. It records architecture, risk hypotheses,
coverage warnings, and manual-review queues so that zero findings are not treated
as proof of safety.
"""

from __future__ import annotations

import argparse
import json
import re
import tempfile
from pathlib import Path
from typing import Any

from public_corpus_importer import PUBLIC_ROOT, ensure_public_corpus
from solidity_fixture_indexer import index_project
from source_coverage_gate import LIFECYCLE_RE, evaluate_project, find_case_context, split_csv


def classify_contract(name: str) -> str:
    lowered = name.lower()
    for token, role in [("oracle", "oracle"), ("vault", "vault"), ("market", "market/lending"), ("controller", "controller"), ("factory", "factory"), ("token", "token"), ("deposit", "deposit-pool"), ("strategy", "strategy"), ("escrow", "escrow"), ("policy", "governance")]:
        if token in lowered:
            return role
    return "unknown"


def triage_project(case_root: Path, *, case_id: str | None = None) -> dict[str, Any]:
    idx = index_project(case_root, include_tests=False)
    coverage = evaluate_project(case_root, case_id=case_id or case_root.name)
    contracts = [contract for row in idx.get("files", []) for contract in row.get("contracts", [])]
    functions = [fn | {"contract": contract.get("name"), "file_path": row.get("path")} for row in idx.get("files", []) for contract in row.get("contracts", []) for fn in contract.get("functions", [])]
    public_external = [fn for fn in functions if fn.get("visibility") in {"public", "external"}]
    lifecycle = [fn for fn in public_external if LIFECYCLE_RE.search(str(fn.get("name") or ""))]
    imports = sorted({m.group(0).strip() for row in idx.get("files", []) if row.get("kind") == "solidity" for m in re.finditer(r"^\s*import\s+[^;]+;", str(row.get("text") or ""), re.M)})[:50]
    architecture = [{"contract": c.get("name"), "kind": c.get("kind"), "role": classify_contract(str(c.get("name") or "")), "inherits": c.get("inherits", [])} for c in contracts]
    role_graph = [{"contract": c.get("name"), "inherits": c.get("inherits", []), "role_tokens": [token for token in ["owner", "admin", "governance", "controller", "borrower"] if token in str(c.get("body", "")).lower()]} for c in contracts]
    attack_surface = [{"contract": fn.get("contract"), "function": fn.get("name"), "visibility": fn.get("visibility"), "modifiers": fn.get("modifiers", []), "file_path": fn.get("file_path")} for fn in public_external[:200]]
    lifecycle_map = [{"contract": fn.get("contract"), "function": fn.get("name"), "file_path": fn.get("file_path")} for fn in lifecycle[:100]]
    hypotheses = []
    for fn in lifecycle[:20]:
        hypotheses.append({
            "state": "HYPOTHESIS_ONLY",
            "contract": fn.get("contract"),
            "function": fn.get("name"),
            "hypothesis": f"Because users or privileged actors can call {fn.get('contract')}.{fn.get('name')} in a lifecycle path, manually review whether accounting, role, and external-call assumptions remain synchronized across sibling paths.",
            "counts_as_finding": False,
        })
    manual_queue = []
    if coverage["raw_lead_count"] == 0:
        manual_queue.append("Zero raw leads from a large/source-rich repo require manual source-to-lead generation review.")
    if coverage["external_calls_indexed"]:
        manual_queue.append("Review external calls and token transfers for ordering and accounting assumptions.")
    if coverage["role_checks_indexed"]:
        manual_queue.append("Review role graph and sibling access-control consistency.")
    return {
        "case_id": case_id or case_root.name,
        "artifact_type": "real_protocol_triage_not_vulnerability_report",
        "confirmed_findings_statement": "No confirmed findings; this is not proof the protocol is safe.",
        "architecture_map": architecture,
        "role_graph": role_graph,
        "external_dependency_map": {"imports_sample": imports, "external_calls_indexed": coverage["external_calls_indexed"], "token_transfers_indexed": coverage["token_transfers_indexed"]},
        "lifecycle_map": lifecycle_map,
        "attack_surface_map": attack_surface,
        "top_risk_hypotheses": hypotheses,
        "manual_review_queue": manual_queue,
        "coverage_warnings": coverage.get("blocks", []),
        "blocked_detection_reasons": ["source_to_lead_generation_failure"] if coverage["raw_lead_count"] == 0 else [],
        "coverage": coverage,
        "protocol_marked_safe": False,
    }


def triage_cases(root: Path, case_ids: list[str], *, write: bool = True) -> dict[str, Any]:
    ensure_public_corpus(root)
    rows = []
    for case_id in case_ids:
        eval_root, case_root = find_case_context(root, case_id)
        artifact = triage_project(case_root, case_id=case_id)
        if write:
            out = eval_root / "scoring" / "triage" / f"{case_id}.json"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(artifact, indent=2) + "\n")
            artifact = {**artifact, "triage_path": out.relative_to(eval_root).as_posix()}
        rows.append(artifact)
    return {"status": "PASS", "cases": rows}


def self_test() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "proto"
        (root / "src").mkdir(parents=True)
        (root / "src" / "Vault.sol").write_text("pragma solidity ^0.8.20; contract Vault { address owner; modifier onlyOwner(){require(msg.sender == owner); _;} function deposit() external payable {} function withdraw(address payable to) external onlyOwner { to.transfer(1); } }")
        artifact = triage_project(root, case_id="proto")
        ok = artifact["architecture_map"] and artifact["top_risk_hypotheses"] and artifact["protocol_marked_safe"] is False and "No confirmed findings" in artifact["confirmed_findings_statement"]
        return {"status": "PASS" if ok else "FAIL", "artifact": artifact}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Generate conservative real-protocol triage artifacts")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--cases", default="")
    p.add_argument("--project-root", default="")
    p.add_argument("--case-id", default="")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        result = self_test()
    elif args.project_root:
        result = triage_project(Path(args.project_root), case_id=args.case_id or Path(args.project_root).name)
    elif args.cases:
        result = triage_cases(Path(args.root), split_csv(args.cases))
    else:
        raise SystemExit("provide --cases, --project-root, or --self-test")
    print(json.dumps(result, indent=2))
    return 0 if result.get("status", "PASS") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
