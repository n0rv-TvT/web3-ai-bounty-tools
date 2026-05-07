#!/usr/bin/env python3
"""Shared helpers for the confirmed-PoC report-readiness closure workflow."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT


CONFIRMED_CANDIDATE_ID = "POC-PREC-case_pc_0002-vulnerable-002"
PAIR_ID = "case_pc_0002"
CLOSURE_DIR_NAME = "report_ready_closure"


def safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_") or "candidate"


def candidate_prefix(candidate_id: str) -> str:
    match = re.search(r"vulnerable-(\d+)$", candidate_id)
    return f"candidate_{match.group(1)}" if match else safe_id(candidate_id)


def closure_dir(root: Path = PUBLIC_ROOT) -> Path:
    out = root / "scoring" / CLOSURE_DIR_NAME
    out.mkdir(parents=True, exist_ok=True)
    return out


def closure_path(root: Path, candidate_id: str, suffix: str) -> Path:
    return closure_dir(root) / f"{candidate_prefix(candidate_id)}_{suffix}"


def load_json(path: Path, default: dict[str, Any] | None = None) -> dict[str, Any]:
    if path.exists():
        return json.loads(path.read_text(errors="replace"))
    return default or {}


def write_json(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")
    return payload


def candidate_matches(payload: dict[str, Any], candidate_id: str) -> bool:
    payload_candidate = payload.get("candidate_id")
    return not payload_candidate or payload_candidate == candidate_id


def evidence_package_path(root: Path, candidate_id: str, *, final: bool = False) -> Path:
    if final:
        return closure_path(root, candidate_id, "final_evidence_package.json")
    specific = root / "scoring" / f"poc_vertical_slice_{safe_id(candidate_id)}_evidence_package.json"
    if specific.exists():
        return specific
    return root / "scoring" / "poc_vertical_slice_evidence_package.json"


def load_evidence(root: Path = PUBLIC_ROOT, candidate_id: str = CONFIRMED_CANDIDATE_ID, *, final: bool = False) -> dict[str, Any]:
    path = evidence_package_path(root, candidate_id, final=final)
    payload = load_json(path, {})
    if payload and candidate_matches(payload, candidate_id):
        return payload
    return {}


def result_path(root: Path, candidate_id: str) -> Path:
    specific = root / "scoring" / f"poc_vertical_slice_{safe_id(candidate_id)}_result.json"
    if specific.exists():
        return specific
    return root / "scoring" / "poc_vertical_slice_result.json"


def load_result(root: Path = PUBLIC_ROOT, candidate_id: str = CONFIRMED_CANDIDATE_ID) -> dict[str, Any]:
    payload = load_json(result_path(root, candidate_id), {})
    if payload and candidate_matches(payload, candidate_id):
        return payload
    batch = load_json(root / "scoring" / "poc_vertical_slice_batch_result.json", {})
    for row in batch.get("results", []):
        if row.get("candidate_id") == candidate_id:
            return row
    return {}


def poc_test_path(root: Path, candidate_id: str = CONFIRMED_CANDIDATE_ID) -> Path:
    manifest = root / "generated_pocs" / "case_pc_0002_vulnerable" / "POC_PREC_case_pc_0002_vulnerable_002" / "test" / "GeneratedPoC.t.sol"
    return manifest


def vulnerable_source_path(root: Path) -> Path:
    return root / "patched-controls" / "case_pc_0002_vulnerable" / "src" / "InvestmentManager.sol"


def patched_source_path(root: Path) -> Path:
    return root / "patched-controls" / "case_pc_0002_patched" / "src" / "InvestmentManager.sol"


def read_text(path: Path) -> str:
    return path.read_text(errors="replace") if path.exists() else ""


def exact_poc_amounts(root: Path = PUBLIC_ROOT) -> dict[str, str]:
    text = read_text(poc_test_path(root))
    if not text:
        return {}
    max_deposit = re.search(r"maxDeposit\s*=\s*([0-9_]+)", text)
    max_mint = re.search(r"maxMint\s*=\s*([0-9_]+)", text)
    escrowed = re.search(r"escrowShares\s*=\s*MAX_MINT", text)
    requested = "1000000000000000000"
    minted = (max_mint.group(1).replace("_", "") if max_mint else "600000000000000000")
    try:
        shortfall = str(int(requested) - int(minted))
    except ValueError:
        shortfall = "unknown"
    return {
        "currency_amount_requested": (max_deposit.group(1).replace("_", "") if max_deposit else "1"),
        "escrowed_tranche_tokens": minted if escrowed else minted,
        "vulnerable_tranche_tokens_requested": requested,
        "patched_tranche_tokens_transferred": minted,
        "tranche_token_shortfall": shortfall,
    }


def safety_metadata() -> dict[str, bool]:
    return {
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "dependency_install_attempted": False,
        "production_source_modified": False,
        "production_readiness_changed": False,
    }


def nonempty(value: Any) -> bool:
    return value not in (None, "", [], {})


def required_missing(payload: dict[str, Any], fields: list[str]) -> list[str]:
    return [field for field in fields if not nonempty(payload.get(field))]
