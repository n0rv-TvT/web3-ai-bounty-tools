#!/usr/bin/env python3
"""Audit why source signals did not become PoC-ready hypotheses.

This is a post-freeze failure-analysis tool. It may read frozen generated
artifacts, local sanitized source, and post-freeze expected-finding metadata,
but it does not fetch network resources, tune detector logic, lower thresholds,
or create findings.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from candidate_rejection_analyzer import analyze_hypothesis
from fresh_expected_finding_extractor import expected_for_case
from fresh_holdout_scoring import score_split
from frozen_output_loader import PUBLIC_ROOT, case_ids_for_split


ALLOWED_MAIN_GAPS = {
    "SOURCE_SIGNAL_NOT_PROMOTED",
    "ROOT_CAUSE_TOO_VAGUE",
    "NO_SOURCE_SIGNAL",
    "MISSING_EXPLOIT_SEQUENCE",
    "MISSING_ASSET",
    "MISSING_ASSERTION",
    "MISSING_POC_IDEA",
    "HUMAN_CONTEXT_REQUIRED",
    "CANDIDATE_SELECTOR_CORRECTLY_REJECTED",
}

SOURCE_SIGNAL_CATEGORIES = {
    "SOURCE_FACT_ABSENT",
    "SOURCE_FACT_PRESENT_BUT_NOT_LINKED",
    "SOURCE_FACT_PRESENT_BUT_COMPONENT_ONLY",
    "SOURCE_FACT_PRESENT_BUT_NO_ROOT_CAUSE",
    "SOURCE_FACT_PRESENT_BUT_NO_ASSET",
    "SOURCE_FACT_PRESENT_BUT_NO_EXPLOIT_SEQUENCE",
    "SOURCE_FACT_PRESENT_AND_HYPOTHESIS_TOO_WEAK",
}


def safe_split_name(split: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "_.-" else "_" for ch in split).replace("-", "_").strip("_") or "split"


def load_json(path: Path, default: Any) -> Any:
    return json.loads(path.read_text(errors="replace")) if path.exists() else default


def count_by(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key) or "")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def find_source_file(root: Path, split: str, case_id: str, source_file: str) -> Path | None:
    case_root = root / split / case_id
    direct = case_root / source_file
    if direct.exists():
        return direct
    name = Path(source_file).name
    if not case_root.exists() or not name:
        return None
    for path in case_root.rglob(name):
        rel = path.relative_to(case_root).as_posix().lower()
        if any(part in rel for part in ["expected_findings/", "public_writeups/", "reports/", "audit_reports/", "issues/"]):
            continue
        if path.is_file():
            return path
    return None


def _word_present(name: str, text: str, prefix: str = "") -> bool:
    if not name:
        return False
    if prefix:
        return bool(re.search(rf"\b{re.escape(prefix)}\s+{re.escape(name)}\b", text))
    return bool(re.search(rf"\b{re.escape(name)}\b", text))


def source_signal(root: Path, split: str, expected: dict[str, Any], gap: dict[str, Any]) -> dict[str, Any]:
    source_file = str(expected.get("source_file") or "")
    source_path = find_source_file(root, split, str(gap.get("case_id") or ""), source_file)
    if not source_path:
        return {
            "source_file_found": False,
            "contract_found": False,
            "function_found": False,
            "source_signal_present": bool(gap.get("related_source_fact")),
            "local_source_component_present": False,
            "source_path": "",
        }
    text = source_path.read_text(errors="replace")
    contract = str(expected.get("affected_contract") or "")
    function = str(expected.get("affected_function") or "")
    contract_found = any(_word_present(contract, text, prefix=kind) for kind in ["contract", "interface", "library"])
    function_found = _word_present(function, text, prefix="function") or _word_present(function, text)
    return {
        "source_file_found": True,
        "contract_found": contract_found,
        "function_found": function_found,
        "source_signal_present": bool(gap.get("related_source_fact")),
        "local_source_component_present": bool(contract_found or function_found),
        "source_path": source_path.relative_to(root / split / str(gap.get("case_id"))).as_posix(),
    }


def load_hypotheses_by_id(root: Path, split: str) -> dict[str, dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for case_id in case_ids_for_split(root, split):
        payload = load_json(root / "generated_reports" / f"{case_id}_hypotheses.json", {"hypotheses": []})
        for h in payload.get("hypotheses", []):
            hid = str(h.get("id") or h.get("lead_id") or h.get("hypothesis_id") or "")
            if hid:
                by_id[hid] = dict(h, case_id=case_id)
    return by_id


def selected_hypothesis_ids(root: Path, split: str) -> set[str]:
    payload = load_json(root / "scoring" / f"{split}_poc_candidate_selection.json", {})
    selected = payload.get("selected_candidates") or payload.get("candidates") or []
    return {str(row.get("hypothesis_id") or row.get("candidate_id") or "") for row in selected if isinstance(row, dict)}


def category_for(*, source_present: bool, match_type: str, match_fields: list[str], audit: dict[str, Any]) -> str:
    if not source_present:
        return "SOURCE_FACT_ABSENT"
    if match_type == "none":
        return "SOURCE_FACT_PRESENT_BUT_NOT_LINKED"
    if match_type == "weak" and "root_cause" not in set(match_fields):
        return "SOURCE_FACT_PRESENT_BUT_COMPONENT_ONLY"
    if audit.get("missing_root_cause"):
        return "SOURCE_FACT_PRESENT_BUT_NO_ROOT_CAUSE"
    if audit.get("missing_affected_asset"):
        return "SOURCE_FACT_PRESENT_BUT_NO_ASSET"
    if audit.get("missing_exploit_sequence"):
        return "SOURCE_FACT_PRESENT_BUT_NO_EXPLOIT_SEQUENCE"
    return "SOURCE_FACT_PRESENT_AND_HYPOTHESIS_TOO_WEAK"


def normalize_gap(gap: str) -> str:
    if gap == "MISSING_POC_PLAN":
        return "MISSING_POC_IDEA"
    return gap if gap in ALLOWED_MAIN_GAPS else "HUMAN_CONTEXT_REQUIRED"


def expected_index_for_split(root: Path, split: str) -> dict[tuple[str, str], dict[str, Any]]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for case_id in case_ids_for_split(root, split):
        for expected in expected_for_case(case_id):
            rows[(case_id, str(expected.get("finding_id") or ""))] = expected
    return rows


def build_expected_gap_map(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation") -> dict[str, Any]:
    score = score_split(root, split=split, frozen_only=True, detailed_gap_map=True)
    raw = load_json(root / "scoring" / "fresh_expected_finding_gap_map.json", {"gaps": []})
    expected_by_key = expected_index_for_split(root, split)
    hypotheses = load_hypotheses_by_id(root, split)
    selected_ids = selected_hypothesis_ids(root, split)
    rows: list[dict[str, Any]] = []
    for gap in raw.get("gaps", []):
        case_id = str(gap.get("case_id") or "")
        finding_id = str(gap.get("expected_finding_id") or "")
        expected = expected_by_key.get((case_id, finding_id), {})
        hyp_id = str(gap.get("related_hypothesis_id") or "")
        hyp = hypotheses.get(hyp_id, {}) if gap.get("related_hypothesis_match_type") != "none" else {}
        audit = analyze_hypothesis(hyp) if hyp else {}
        sig = source_signal(root, split, expected, gap)
        match_type = str(gap.get("related_hypothesis_match_type") or "none")
        match_fields = []
        for case in score.get("cases", []):
            if case.get("case_id") != case_id:
                continue
            for match in case.get("hypothesis_matches", []):
                if match.get("expected_finding_id") == finding_id:
                    match_fields = list(match.get("matched_fields") or [])
                    break
        row = {
            "case_id": case_id,
            "expected_finding_id": finding_id,
            "expected_title": gap.get("expected_title"),
            "expected_severity": gap.get("expected_severity"),
            "related_hypothesis": bool(gap.get("related_hypothesis")),
            "related_hypothesis_id": hyp_id if gap.get("related_hypothesis") else "",
            "match_type": match_type,
            "matched_fields": match_fields,
            "related_source_signal": bool(sig.get("source_signal_present")),
            "source_file_found": bool(sig.get("source_file_found")),
            "source_contract_found": bool(sig.get("contract_found")),
            "source_function_found": bool(sig.get("function_found")),
            "local_source_component_present": bool(sig.get("local_source_component_present")),
            "source_path": sig.get("source_path"),
            "related_attack_surface_entry": bool(gap.get("related_attack_surface_entry")),
            "related_lifecycle": bool(gap.get("related_lifecycle")),
            "related_asset_flow": bool(gap.get("related_asset_flow")),
            "candidate_selected": bool(hyp_id and hyp_id in selected_ids),
            "main_gap": normalize_gap(str(gap.get("main_gap") or "")),
            "source_signal_category": category_for(source_present=bool(sig.get("source_signal_present")), match_type=match_type, match_fields=match_fields, audit=audit),
            "required_general_upgrade": gap.get("required_general_upgrade"),
            "answer_key_text_dependency": False,
            "counts_toward_readiness": False,
        }
        rows.append(row)
    payload = {
        "status": "PASS" if rows else "BLOCKED",
        "split": split,
        "expected_finding_count": len(rows),
        "main_gap_counts": count_by(rows, "main_gap"),
        "source_signal_category_counts": count_by(rows, "source_signal_category"),
        "source_signal_present_count": sum(1 for row in rows if row.get("related_source_signal")),
        "candidate_selected_count": sum(1 for row in rows if row.get("candidate_selected")),
        "gaps": rows,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "dependency_install_attempted": False,
        "detector_tuning_performed": False,
        "thresholds_weakened": False,
        "counts_toward_readiness": False,
    }
    scoring = root / "scoring"
    scoring.mkdir(parents=True, exist_ok=True)
    split_name = safe_split_name(split)
    (scoring / f"{split_name}_expected_finding_gap_map.json").write_text(json.dumps(payload, indent=2) + "\n")
    return payload


def run_audit(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation") -> dict[str, Any]:
    gap_map = build_expected_gap_map(root, split=split)
    rows = gap_map.get("gaps", [])
    payload = {
        "status": gap_map.get("status"),
        "split": split,
        "classification": "posthoc_failure_analysis_only",
        "expected_finding_count": len(rows),
        "category_counts": gap_map.get("source_signal_category_counts", {}),
        "main_gap_counts": gap_map.get("main_gap_counts", {}),
        "source_signals_present": sum(1 for row in rows if row.get("related_source_signal")),
        "source_signals_not_promoted": sum(1 for row in rows if row.get("source_signal_category") in {"SOURCE_FACT_PRESENT_BUT_NOT_LINKED", "SOURCE_FACT_PRESENT_BUT_COMPONENT_ONLY"}),
        "rows": rows,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "dependency_install_attempted": False,
        "report_ready_created": False,
        "counts_as_finding": False,
        "counts_toward_readiness": False,
    }
    scoring = root / "scoring"
    split_name = safe_split_name(split)
    (scoring / f"{split_name}_source_signal_promotion_audit.json").write_text(json.dumps(payload, indent=2) + "\n")
    return payload


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Audit source-signal promotion failures after frozen detection")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="fresh-confirmation")
    p.add_argument("--frozen-only", action="store_true")
    args = p.parse_args(argv)
    result = run_audit(Path(args.root), split=args.split)
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
