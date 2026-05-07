#!/usr/bin/env python3
"""Shared helpers for post-freeze expected-aligned precision repair.

These helpers operate only on already-frozen generated artifacts and local
sanitized source. They are post-hoc failure-analysis utilities, not detector
logic, and they never count repaired output toward readiness.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from fresh_expected_finding_extractor import expected_for_case
from frozen_output_loader import PUBLIC_ROOT, case_ids_for_split, load_case_outputs


REPAIR_DIR_NAME = "fresh_v6_expected_aligned_repair"
MATCH_RANK = {"strict": 4, "semantic": 3, "weak": 2, "none": 0, "": 0}
REPAIR_RANK = {"high": 3, "medium": 2, "low": 1, "kill": 0, "": 0}


def repair_dir(root: Path = PUBLIC_ROOT) -> Path:
    out = root / "scoring" / REPAIR_DIR_NAME
    out.mkdir(parents=True, exist_ok=True)
    return out


def load_json(path: Path, default: Any | None = None) -> Any:
    return json.loads(path.read_text(errors="replace")) if path.exists() else ({} if default is None else default)


def write_json(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")
    return payload


def safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "candidate"


def load_expected_rows(root: Path, split: str, case_id: str) -> list[dict[str, Any]]:
    expected_path = root / "expected_findings" / split / f"{case_id}.json"
    if expected_path.exists():
        payload = load_json(expected_path, {})
        return [dict(row, case_id=case_id) for row in payload.get("all_expected_findings", [])]
    return expected_for_case(case_id)


def expected_rows_for_split(root: Path, split: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case_id in case_ids_for_split(root, split):
        rows.extend(load_expected_rows(root, split, case_id))
    return rows


def load_frozen_hypotheses(root: Path, case_id: str) -> list[dict[str, Any]]:
    loaded = load_case_outputs(root, case_id, required_suffixes=["hypotheses"])
    if loaded.get("status") == "PASS":
        rows = loaded["artifacts"]["hypotheses"].get("hypotheses", [])
    else:
        rows = load_json(root / "generated_reports" / f"{case_id}_hypotheses.json", {"hypotheses": []}).get("hypotheses", [])
    return [dict(row, case_id=case_id) for row in rows]


def load_frozen_manual_items(root: Path, case_id: str) -> list[dict[str, Any]]:
    loaded = load_case_outputs(root, case_id, required_suffixes=["manual_review_queue"])
    if loaded.get("status") == "PASS":
        rows = loaded["artifacts"]["manual_review_queue"].get("items", [])
    else:
        rows = load_json(root / "generated_reports" / f"{case_id}_manual_review_queue.json", {"items": []}).get("items", [])
    return [dict(row, case_id=case_id) for row in rows]


def hypothesis_id(item: dict[str, Any]) -> str:
    return str(item.get("id") or item.get("lead_id") or item.get("hypothesis_id") or item.get("queue_id") or "")


def find_hypothesis(root: Path, case_id: str, hyp_id: str) -> dict[str, Any] | None:
    for row in load_frozen_hypotheses(root, case_id):
        if hypothesis_id(row) == hyp_id:
            return row
    return None


def load_score(root: Path) -> dict[str, Any]:
    return load_json(root / "scoring" / "fresh_holdout_score.json", {})


def load_gap_map(root: Path) -> dict[str, Any]:
    return load_json(root / "scoring" / "fresh_expected_finding_gap_map.json", {"gaps": []})


def gap_by_expected(root: Path) -> dict[tuple[str, str], dict[str, Any]]:
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for row in load_gap_map(root).get("gaps", []):
        out[(str(row.get("case_id") or ""), str(row.get("expected_finding_id") or ""))] = row
    return out


def score_case_by_id(root: Path) -> dict[str, dict[str, Any]]:
    return {str(case.get("case_id")): case for case in load_score(root).get("cases", [])}


def match_for(case: dict[str, Any], key: str, expected_id: str) -> dict[str, Any]:
    for row in case.get(key, []):
        if str(row.get("expected_finding_id") or "") == expected_id:
            return row
    return {"match_type": "none", "generated_id": "", "matched_fields": []}


def source_root_for(root: Path, split: str, case_id: str) -> Path:
    return root / split / case_id


def source_path_for(root: Path, split: str, case_id: str, file_path: str) -> Path:
    return source_root_for(root, split, case_id) / file_path


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, max(offset, 0)) + 1


def function_name_before(text: str, offset: int) -> str:
    prefix = text[:offset]
    matches = list(re.finditer(r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", prefix))
    return matches[-1].group(1) if matches else ""


def contract_name_for(text: str) -> str:
    match = re.search(r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)\b", text)
    return match.group(1) if match else ""


def load_selection(root: Path) -> dict[str, Any]:
    return load_json(repair_dir(root) / "expected_related_repair_selection.json", {})


def load_selected_candidate(root: Path) -> dict[str, Any]:
    sel = load_selection(root)
    return sel.get("selected_candidate") or sel


def selected_candidate_id(root: Path) -> str:
    return str(load_selected_candidate(root).get("candidate_id") or "")


def base_result_flags() -> dict[str, Any]:
    return {
        "answer_key_access": False,
        "writeup_access": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "dependency_install_attempted": False,
        "detector_tuning_performed": False,
        "counts_toward_readiness": False,
        "production_readiness_changed": False,
        "report_ready_created": False,
        "counts_as_finding": False,
    }
