#!/usr/bin/env python3
"""Extract public contest expected findings after blind reports are frozen.

This script is intentionally post-freeze only: it refuses to create an answer
key unless the generated detector report for the case already exists and passes
the frozen-report hash verification.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from artifact_hasher import verify_frozen_report
from public_corpus_importer import PUBLIC_ROOT


EIGENLAYER_2023_04_FINDINGS: list[dict[str, Any]] = [
    {
        "finding_id": "H-01",
        "title": "Slot and block number proofs not required for verification of withdrawal allows multiple withdrawals",
        "bug_class": "invalid-validation",
        "root_cause_rule": "missing_proof_length_validation",
        "source_file": "src/contracts/libraries/BeaconChainProofs.sol",
        "affected_contract": "BeaconChainProofs",
        "affected_function": "verifyWithdrawalProofs",
        "secondary_components": ["src/contracts/pods/EigenPod.sol::EigenPod.verifyAndProcessWithdrawal", "src/contracts/libraries/Merkle.sol::Merkle.verifyInclusionSha256"],
        "affected_asset": "ETH/restaked withdrawal funds",
        "impact_type": "stolen-funds",
        "expected_severity": "High",
        "exploit_path_tokens": ["empty proof", "multiple withdrawals", "funds can be stolen"],
        "public_issue_url": "https://github.com/code-423n4/2023-04-eigenlayer-findings/issues/388",
    },
    {
        "finding_id": "H-02",
        "title": "Misplaced loop increment prevents skipping malicious strategy during slashing",
        "bug_class": "loop-logic",
        "root_cause_rule": "misplaced_loop_increment_in_skip_branch",
        "source_file": "src/contracts/core/StrategyManager.sol",
        "affected_contract": "StrategyManager",
        "affected_function": "slashQueuedWithdrawal",
        "affected_asset": "queued withdrawal/slashing funds",
        "impact_type": "frozen-funds-or-slashing-bypass",
        "expected_severity": "High",
        "exploit_path_tokens": ["indicesToSkip", "++i", "malicious strategy"],
        "public_issue_url": "https://github.com/code-423n4/2023-04-eigenlayer-findings/issues/205",
    },
    {
        "finding_id": "M-01",
        "title": "Over-committed staker can avoid slashing after shares are temporarily reduced",
        "bug_class": "accounting-desync",
        "root_cause_rule": "overcommitment_not_accounted_during_slashing",
        "source_file": "src/contracts/core/StrategyManager.sol",
        "affected_contract": "StrategyManager",
        "affected_function": "slashShares",
        "secondary_components": ["src/contracts/pods/EigenPod.sol::EigenPod.verifyOverCommittedStake"],
        "affected_asset": "restaked shares subject to slashing",
        "impact_type": "slashing-bypass",
        "expected_severity": "Medium",
        "exploit_path_tokens": ["over-commitment", "bypass slashing", "shares credited back"],
        "public_issue_url": "https://github.com/code-423n4/2023-04-eigenlayer-findings/issues/408",
    },
    {
        "finding_id": "M-02",
        "title": "Reverting strategy can block pending withdrawals that contain it",
        "bug_class": "incomplete-withdrawal-path",
        "root_cause_rule": "queued_withdrawal_no_skip_or_cancel_for_reverting_strategy",
        "source_file": "src/contracts/core/StrategyManager.sol",
        "affected_contract": "StrategyManager",
        "affected_function": "completeQueuedWithdrawal",
        "affected_asset": "pending withdrawal tokens/shares",
        "impact_type": "frozen-funds",
        "expected_severity": "Medium",
        "exploit_path_tokens": ["malicious strategy", "revert", "pending withdrawals"],
        "public_issue_url": "https://github.com/code-423n4/2023-04-eigenlayer-findings/issues/132",
    },
]


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace"))


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")


def require_frozen_report(root: Path, case_id: str) -> dict[str, Any]:
    report_path = root / "generated_reports" / f"{case_id}.json"
    if not report_path.exists():
        raise SystemExit(f"generated report missing for {case_id}; run blind detection and freeze first")
    report = load_json(report_path)
    if not verify_frozen_report(report):
        raise SystemExit(f"generated report for {case_id} is not frozen; run freeze before expected extraction")
    if report.get("answer_key_loaded") or report.get("answer_key_read_during_detection") or report.get("writeup_read_during_detection"):
        raise SystemExit(f"detection isolation failed for {case_id}; refusing expected extraction")
    return report


def extract_eigenlayer_expected(root: Path, *, case_id: str, report_url: str, report_sha256: str) -> dict[str, Any]:
    report = require_frozen_report(root, case_id)
    primary = dict(EIGENLAYER_2023_04_FINDINGS[0])
    expected = {
        "case_id": case_id,
        "is_vulnerable": True,
        "is_patched_control": False,
        "source_type": "public_contest",
        "expected_source_url": report_url,
        "expected_source_sha256": report_sha256,
        "expected_extracted_after_freeze": True,
        "frozen_generated_report_hash": report.get("report_hash"),
        "all_expected_findings": EIGENLAYER_2023_04_FINDINGS,
        **primary,
    }
    write_json(root / "expected_findings" / f"{case_id}.json", expected)

    manifest_path = root / "corpus_manifest.json"
    manifest = load_json(manifest_path)
    for case in manifest.get("cases", []):
        if case.get("case_id") == case_id:
            case["scoring_enabled"] = True
            case["expected_extraction_status"] = "extracted_after_generated_report_freeze"
            case["expected_source_url"] = report_url
            case["expected_source_sha256"] = report_sha256
            case["expected_finding_count"] = len(EIGENLAYER_2023_04_FINDINGS)
    write_json(manifest_path, manifest)

    write_json(root / "sources" / f"{case_id}_expected_extraction_log.json", {
        "case_id": case_id,
        "extracted_at": datetime.now(timezone.utc).isoformat(),
        "report_url": report_url,
        "report_sha256": report_sha256,
        "frozen_generated_report_hash": report.get("report_hash"),
        "expected_finding_count": len(EIGENLAYER_2023_04_FINDINGS),
        "answer_key_access_timing": "after generated report freeze only",
    })
    return {"status": "PASS", "case_id": case_id, "expected_finding_count": len(EIGENLAYER_2023_04_FINDINGS), "expected_path": f"expected_findings/{case_id}.json"}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Extract contest expected findings after frozen report")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--case-id", default="case_0007")
    p.add_argument("--report-url", default="https://code4rena.com/reports/2023-04-eigenlayer")
    p.add_argument("--report-sha256", required=True)
    args = p.parse_args(argv)
    result = extract_eigenlayer_expected(Path(args.root), case_id=args.case_id, report_url=args.report_url, report_sha256=args.report_sha256)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
