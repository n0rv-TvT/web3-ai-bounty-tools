#!/usr/bin/env python3
"""Select spent fresh-holdout hypotheses for post-hoc PoC-readiness repair.

This module only reads frozen generated artifacts and post-freeze failure-analysis
summaries. It does not create findings, does not tune detector logic, and does
not count repaired candidates toward readiness.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from candidate_rejection_analyzer import analyze_hypothesis
from frozen_output_loader import PUBLIC_ROOT, case_ids_for_split, load_case_outputs


VALUE_KEYWORDS = {
    "asset",
    "token",
    "supply",
    "withdraw",
    "deposit",
    "claim",
    "reward",
    "accounting",
    "signature",
    "permit",
    "oracle",
    "price",
    "amm",
    "swap",
    "stake",
    "role",
    "access",
}


def load_json(path: Path, default: Any) -> Any:
    return json.loads(path.read_text(errors="replace")) if path.exists() else default


def safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "candidate"


def candidate_id_for(case_id: str, hypothesis_id: str) -> str:
    return safe_id(f"REPAIR-POC-{case_id}-{hypothesis_id}")


def selection_path(root: Path) -> Path:
    return root / "scoring" / "repair_to_poc_candidate_selection.json"


def all_hypotheses(root: Path, split: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case_id in case_ids_for_split(root, split):
        loaded = load_case_outputs(root, case_id, required_suffixes=["hypotheses"])
        if loaded.get("status") == "PASS":
            hyps = loaded["artifacts"]["hypotheses"].get("hypotheses", [])
        else:
            hyps = load_json(root / "generated_reports" / f"{case_id}_hypotheses.json", {"hypotheses": []}).get("hypotheses", [])
        rows.extend(dict(h, case_id=case_id) for h in hyps)
    return rows


def candidate_identity(candidate: dict[str, Any]) -> set[str]:
    return {str(v) for v in [candidate.get("candidate_id"), candidate.get("hypothesis_id")] if v}


def load_candidate_selection(root: Path) -> dict[str, Any]:
    return load_json(selection_path(root), {})


def selected_candidate_records(root: Path) -> list[dict[str, Any]]:
    payload = load_candidate_selection(root)
    rows: list[dict[str, Any]] = []
    primary = payload.get("primary_candidate")
    if isinstance(primary, dict) and primary:
        rows.append(primary)
    rows.extend([r for r in payload.get("backup_candidates", []) if isinstance(r, dict)])
    rows.extend([r for r in payload.get("selected_candidates", []) if isinstance(r, dict)])
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        key = str(row.get("candidate_id") or row.get("hypothesis_id") or len(seen))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped


def find_candidate_record(root: Path, candidate: str = "") -> dict[str, Any] | None:
    records = selected_candidate_records(root)
    if not candidate:
        return records[0] if records else None
    for row in records:
        if candidate in candidate_identity(row):
            return row
    return None


def find_hypothesis_for_candidate(root: Path, split: str, candidate: str = "") -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Resolve a selected repair candidate to its frozen hypothesis.

    Returns ``(candidate_record, hypothesis)``. The fallback scan allows tests to
    call candidate-specific helpers with a raw hypothesis id before running the
    selection step, without reading any non-frozen source or answer-key data.
    """

    record = find_candidate_record(root, candidate)
    target_case = str(record.get("case_id") or "") if record else ""
    target_hypothesis = str((record or {}).get("hypothesis_id") or candidate or "")
    for h in all_hypotheses(root, split):
        hid = str(h.get("id") or h.get("lead_id") or h.get("hypothesis_id") or "")
        case_id = str(h.get("case_id") or "")
        if target_hypothesis and hid != target_hypothesis:
            continue
        if target_case and case_id != target_case:
            continue
        resolved_record = record or candidate_record(h, match_index(root))
        return resolved_record, h
    if not record:
        return None, None
    for h in all_hypotheses(root, split):
        hid = str(h.get("id") or h.get("lead_id") or h.get("hypothesis_id") or "")
        if hid == str(record.get("hypothesis_id")) and str(h.get("case_id") or "") == str(record.get("case_id") or ""):
            return record, h
    return record, None


def match_index(root: Path) -> dict[str, dict[str, Any]]:
    idx: dict[str, dict[str, Any]] = {}
    for path, match_type in [
        (root / "scoring" / "strict_match_postmortem.json", "strict"),
        (root / "scoring" / "weak_match_postmortem.json", "weak"),
    ]:
        payload = load_json(path, {"rows": []})
        for row in payload.get("rows", []):
            hid = str(row.get("hypothesis_id") or "")
            if not hid:
                continue
            idx[hid] = {
                "match_type": match_type,
                "expected_finding_related": True,
                "expected_finding_id": row.get("expected_finding_id"),
            }
    return idx


def has_value_keyword(h: dict[str, Any]) -> bool:
    blob = " ".join(str(h.get(k) or "") for k in ["bug_class", "function", "contract", "exploit_scenario", "affected_asset"]).lower()
    return any(word in blob for word in VALUE_KEYWORDS)


def gap(value: bool, text: str) -> str:
    return text if value else ""


def repairability_for(audit: dict[str, Any], match_type: str, h: dict[str, Any]) -> str:
    if audit.get("should_be_killed"):
        return "kill"
    exact = not (audit.get("missing_file") or audit.get("missing_contract") or audit.get("missing_function"))
    if match_type in {"strict", "semantic"} and exact:
        return "high"
    if match_type == "weak" and exact:
        return "medium"
    if exact and has_value_keyword(h):
        return "medium"
    return "low"


def candidate_record(h: dict[str, Any], matches: dict[str, dict[str, Any]]) -> dict[str, Any]:
    hid = str(h.get("id") or h.get("lead_id") or h.get("hypothesis_id"))
    case_id = str(h.get("case_id") or "")
    audit = analyze_hypothesis(h)
    match = matches.get(hid, {"match_type": "none", "expected_finding_related": False})
    match_type = str(match.get("match_type") or "none")
    repairability = repairability_for(audit, match_type, h)
    reason_parts = []
    if match_type == "strict":
        reason_parts.append("single strict hypothesis match has priority")
    elif match_type == "weak":
        reason_parts.append("weak match is closer to semantic than unrelated leads")
    if has_value_keyword(h):
        reason_parts.append("source facts involve value movement, accounting, signatures, oracle, staking/reward, or permission boundary")
    if repairability == "kill":
        reason_parts.append("rejected as component-only/test/mock noise before PoC work")
    elif not reason_parts:
        reason_parts.append("exact source location is repairable but lacks match priority")
    return {
        "candidate_id": candidate_id_for(case_id, hid),
        "hypothesis_id": hid,
        "case_id": case_id,
        "original_quality_score": audit.get("quality_score", 0.0),
        "match_type": match_type,
        "expected_finding_related": bool(match.get("expected_finding_related")),
        "expected_finding_id": match.get("expected_finding_id"),
        "file": h.get("file_path") or h.get("file"),
        "contract": h.get("contract"),
        "function": h.get("function"),
        "bug_class": h.get("bug_class"),
        "root_cause_gap": gap(audit.get("missing_root_cause"), "root cause is missing or broad"),
        "asset_gap": gap(audit.get("missing_affected_asset"), "affected asset/state is generic and must be derived from source facts"),
        "exploit_sequence_gap": gap(audit.get("missing_exploit_sequence"), "ordered setup/attack/proof sequence is missing or generic"),
        "state_setup_gap": "state setup must identify roles, balances, approvals, prior lifecycle, and mocks without inventing constructor args",
        "assertion_gap": gap(audit.get("missing_assertion"), "concrete balance/state assertion is missing"),
        "kill_condition_gap": gap(audit.get("missing_kill_condition"), "kill condition is missing"),
        "repairability": repairability,
        "selection_reason": "; ".join(reason_parts),
        "pre_repair_audit": audit,
        "report_ready": False,
        "counts_as_finding": False,
        "counts_toward_readiness": False,
    }


def priority(row: dict[str, Any]) -> tuple[int, int, int, float]:
    if row.get("repairability") == "kill":
        return (-1, 0, 0, 0.0)
    match_score = {"strict": 4, "semantic": 3, "weak": 2, "none": 0}.get(str(row.get("match_type")), 0)
    repair_score = {"high": 3, "medium": 2, "low": 1, "kill": 0}.get(str(row.get("repairability")), 0)
    expected = 1 if row.get("expected_finding_related") else 0
    quality = float(row.get("original_quality_score") or 0.0)
    return (match_score, repair_score, expected, quality)


def select_repair_candidates(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation", backup_limit: int = 5) -> dict[str, Any]:
    matches = match_index(root)
    rows = [candidate_record(h, matches) for h in all_hypotheses(root, split)]
    selectable = [r for r in rows if r.get("repairability") != "kill"]
    selectable.sort(key=priority, reverse=True)
    primary = selectable[0] if selectable else None
    backup = selectable[1 : 1 + backup_limit]
    selected_ids = {r["candidate_id"] for r in ([primary] if primary else []) + backup}
    rejected = [r for r in rows if r["candidate_id"] not in selected_ids]
    result = {
        "status": "PASS" if primary else "BLOCKED",
        "split": split,
        "primary_candidate": primary,
        "backup_candidates": backup,
        "rejected_candidates": rejected,
        "selection_policy": [
            "strict matches first if repairable",
            "weak matches closest to semantic next",
            "then exact value-moving/accounting/signature/oracle/staking/permission-boundary hypotheses",
            "never select component-only/test/mock noise",
        ],
        "selected_count": (1 if primary else 0) + len(backup),
        "rejected_count": len(rejected),
        "answer_key_access": False,
        "writeup_access": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "detector_tuning_performed": False,
        "thresholds_weakened": False,
        "report_ready_created": False,
        "counts_as_finding": False,
        "production_readiness_changed": False,
        "counts_toward_readiness": False,
    }
    out = selection_path(root)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Select post-hoc repair candidates for PoC-readiness")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="fresh-confirmation")
    p.add_argument("--backup-limit", type=int, default=5)
    args = p.parse_args(argv)
    result = select_repair_candidates(Path(args.root), split=args.split, backup_limit=args.backup_limit)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
