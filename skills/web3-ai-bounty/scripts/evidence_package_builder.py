#!/usr/bin/env python3
"""Build/standardize evidence packages from vertical-slice results."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT
from evidence_package_validator import validate_package


def safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_") or "candidate"


def load_json(path: Path, default: dict[str, Any] | None = None) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace")) if path.exists() else (default or {})


def candidate_matches(payload: dict[str, Any], candidate_id: str) -> bool:
    payload_candidate = payload.get("candidate_id")
    return not payload_candidate or payload_candidate == candidate_id


def batch_result_for(root: Path, candidate_id: str) -> dict[str, Any]:
    batch = load_json(root / "scoring" / "poc_vertical_slice_batch_result.json", {})
    for row in batch.get("results", []):
        if row.get("candidate_id") == candidate_id:
            return row
    return {}


def candidate_info(root: Path, candidate_id: str) -> dict[str, Any]:
    for path in [root / "scoring" / "poc_vertical_slice_batch_selection.json", root / "scoring" / "poc_vertical_slice_candidate_selection.json"]:
        payload = load_json(path, {})
        for c in payload.get("selected_candidates", []):
            if c.get("candidate_id") == candidate_id:
                return c
        if payload.get("selected_candidate_id") == candidate_id:
            return {"candidate_id": candidate_id, "pair_id": payload.get("pair_id"), "file": payload.get("file"), "contract": payload.get("contract"), "function": payload.get("function"), "bug_class": payload.get("bug_class"), "attacker_capability": payload.get("attacker_capability"), "affected_asset": payload.get("affected_asset"), "exploit_sequence": payload.get("exploit_sequence")}
    return {"candidate_id": candidate_id}


def result_for(root: Path, candidate_id: str) -> dict[str, Any]:
    specific = load_json(root / "scoring" / f"poc_vertical_slice_{safe_id(candidate_id)}_result.json", {})
    if specific and candidate_matches(specific, candidate_id):
        return specific
    batch = batch_result_for(root, candidate_id)
    if batch:
        return batch
    generic = load_json(root / "scoring" / "poc_vertical_slice_result.json", {})
    if generic and candidate_matches(generic, candidate_id):
        return generic
    return {}


def existing_package(root: Path, candidate_id: str) -> dict[str, Any]:
    specific = load_json(root / "scoring" / f"poc_vertical_slice_{safe_id(candidate_id)}_evidence_package.json", {})
    if specific and candidate_matches(specific, candidate_id):
        return specific
    generic = load_json(root / "scoring" / "poc_vertical_slice_evidence_package.json", {})
    if generic and candidate_matches(generic, candidate_id):
        return generic
    return {}


def build_package(root: Path = PUBLIC_ROOT, *, candidate_id: str) -> dict[str, Any]:
    info = candidate_info(root, candidate_id)
    result = result_for(root, candidate_id)
    existing = existing_package(root, candidate_id)
    poc_result = result.get("result") or existing.get("poc_result")
    patched_regression_result = result.get("patched_test_status") or existing.get("patched_regression_result")
    confirmed = poc_result == "POC_PASS_CONFIRMS_HYPOTHESIS"
    killed = poc_result == "POC_FAILS_KILLS_HYPOTHESIS"
    package = {
        "candidate_id": candidate_id,
        "pair_id": info.get("pair_id") or existing.get("pair_id"),
        "file": info.get("file") or info.get("file_path") or existing.get("file"),
        "contract": info.get("contract") or existing.get("contract"),
        "function": info.get("function") or existing.get("function"),
        "vulnerable_code_path": existing.get("vulnerable_code_path") or f"{info.get('contract')}.{info.get('function')}",
        "preconditions": existing.get("preconditions") or ["post-hoc patched-control harness", "same attack steps used where possible", "local generated PoC executed"],
        "attacker_capability": info.get("attacker_capability") or existing.get("attacker_capability"),
        "affected_asset": existing.get("affected_asset") or info.get("affected_asset") or "security-sensitive state under test",
        "exploit_sequence": existing.get("exploit_sequence") or info.get("exploit_sequence") or ["execute generated vertical-slice test"],
        "impact": existing.get("impact") or ("hypothesis killed; no concrete impact confirmed" if killed else "post-hoc impact confirmed by local vertical-slice harness"),
        "likelihood": existing.get("likelihood") or ("not applicable because hypothesis was killed" if killed else "post-hoc reproduction only; not a live likelihood claim"),
        "severity_rationale": existing.get("severity_rationale") or ("No severity because the hypothesis was killed." if killed else "Evidence-backed post-hoc regression, not report-ready without scope/duplicate/economic review."),
        "poc_command": existing.get("poc_command") or "forge test --root . --match-test <vertical_slice> -vvv",
        "poc_result": poc_result,
        "patched_regression_result": patched_regression_result,
        "recommended_fix": existing.get("recommended_fix") or ("No fix proposed because the hypothesis was killed." if killed else "Apply the patch pattern proven by the patched-control regression."),
        "confidence": existing.get("confidence") or ("high confidence this hypothesis is killed" if killed else "medium-high post-hoc confidence"),
        "limitations": existing.get("limitations") or ["post-hoc patched-control evidence only", "not fresh holdout evidence", "not automatically report-ready"],
        "confirmed": confirmed,
        "killed": killed,
        "report_ready": False,
        "production_readiness_changed": False,
    }
    validation = validate_package(package)
    package["validator_status"] = validation["status"]
    out = root / "scoring" / f"poc_vertical_slice_{safe_id(candidate_id)}_evidence_package.json"
    out.write_text(json.dumps(package, indent=2) + "\n")
    if candidate_id == "POC-PREC-case_pc_0002-vulnerable-002":
        (root / "scoring" / "poc_vertical_slice_evidence_package.json").write_text(json.dumps(package, indent=2) + "\n")
    summary = {"status": "PASS" if validation["valid"] else validation["status"], "candidate_id": candidate_id, "evidence_package": str(out.relative_to(root)), "validator": validation, "report_ready_created": False, "production_readiness_changed": False}
    (root / "scoring" / f"poc_vertical_slice_{safe_id(candidate_id)}_evidence_builder_result.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Build standardized vertical-slice evidence package")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--candidate", required=True)
    args = p.parse_args(argv)
    result = build_package(Path(args.root), candidate_id=args.candidate)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
