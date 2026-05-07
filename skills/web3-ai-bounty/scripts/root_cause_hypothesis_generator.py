#!/usr/bin/env python3
"""Generate source-supported root-cause hypotheses for post-hoc repair.

The generator consumes frozen hypotheses and generic source-xray reasons. It can
label whether a row was expected-related based on post-freeze scoring metadata,
but the repaired root-cause text is derived from frozen source signals, not from
report prose or expected finding titles.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from candidate_rejection_analyzer import run_analysis
from frozen_output_loader import PUBLIC_ROOT, case_ids_for_split, load_case_outputs
from repair_to_poc_candidate_selection import candidate_id_for, match_index, select_repair_candidates
from source_fact_to_attack_story_linker import link_hypothesis, source_reasons


def safe_split_name(split: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "_.-" else "_" for ch in split).replace("-", "_").strip("_") or "split"


def hypothesis_id(h: dict[str, Any]) -> str:
    return str(h.get("id") or h.get("lead_id") or h.get("hypothesis_id") or "")


def load_hypotheses(root: Path, split: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case_id in case_ids_for_split(root, split):
        loaded = load_case_outputs(root, case_id, required_suffixes=["hypotheses"])
        payload = loaded.get("artifacts", {}).get("hypotheses") if loaded.get("status") == "PASS" else None
        if payload is None:
            path = root / "generated_reports" / f"{case_id}_hypotheses.json"
            payload = json.loads(path.read_text(errors="replace")) if path.exists() else {"hypotheses": []}
        rows.extend(dict(h, case_id=case_id) for h in payload.get("hypotheses", []))
    return rows


def has_source_evidence(h: dict[str, Any]) -> bool:
    return bool(h.get("external_evidence") or h.get("code_path") or source_reasons(h))


def exact_location(h: dict[str, Any]) -> bool:
    return bool(h.get("file_path") and h.get("contract") and h.get("function"))


def generate_root_cause_hypothesis(h: dict[str, Any], *, match: dict[str, Any] | None = None) -> dict[str, Any]:
    hid = hypothesis_id(h)
    if not has_source_evidence(h):
        return {
            "status": "BLOCKED_MISSING_SOURCE_EVIDENCE",
            "hypothesis_id": hid,
            "case_id": h.get("case_id"),
            "source_supported": False,
            "root_cause_hypothesis": "",
            "answer_key_text_dependency": False,
            "counts_toward_readiness": False,
        }
    linked = link_hypothesis(h)
    if not exact_location(h) or linked.get("link_status") != "LINKED":
        return {
            "status": "BLOCKED_MISSING_EXACT_LOCATION",
            "hypothesis_id": hid,
            "case_id": h.get("case_id"),
            "file_path": h.get("file_path") or h.get("file"),
            "contract": h.get("contract"),
            "function": h.get("function"),
            "source_supported": True,
            "root_cause_hypothesis": linked.get("root_cause"),
            "answer_key_text_dependency": False,
            "counts_toward_readiness": False,
        }
    return {
        "status": "PASS",
        "candidate_id": candidate_id_for(str(h.get("case_id") or ""), hid),
        "hypothesis_id": hid,
        "case_id": h.get("case_id"),
        "file_path": h.get("file_path") or h.get("file"),
        "contract": h.get("contract"),
        "function": h.get("function"),
        "bug_class": h.get("bug_class"),
        "source_reasons": linked.get("source_reasons") or [],
        "root_cause_hypothesis": linked.get("root_cause"),
        "affected_asset_hint": linked.get("affected_asset"),
        "exploit_path_hint": linked.get("exploit_path") or [],
        "expected_finding_related": bool((match or {}).get("expected_finding_related")),
        "expected_finding_id": (match or {}).get("expected_finding_id"),
        "match_type": (match or {}).get("match_type", "none"),
        "source_supported": True,
        "answer_key_text_dependency": False,
        "report_ready": False,
        "counts_as_finding": False,
        "counts_toward_readiness": False,
    }


def run_split(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation") -> dict[str, Any]:
    # Rebuild post-freeze rejection/match files so expected-related labels reflect
    # the requested split and not stale artifacts from another spent run.
    run_analysis(root, split=split)
    selected = select_repair_candidates(root, split=split)
    matches = match_index(root)
    rows = [generate_root_cause_hypothesis(h, match=matches.get(hypothesis_id(h))) for h in load_hypotheses(root, split)]
    pass_rows = [row for row in rows if row.get("status") == "PASS"]
    expected_related = [row for row in pass_rows if row.get("expected_finding_related")]
    payload = {
        "status": "PASS" if rows else "BLOCKED",
        "split": split,
        "classification": "posthoc_root_cause_precision_repair_only",
        "hypothesis_count": len(rows),
        "source_supported_count": sum(1 for row in rows if row.get("source_supported")),
        "root_cause_generated_count": len(pass_rows),
        "expected_related_root_cause_count": len(expected_related),
        "selected_repair_candidate": selected.get("primary_candidate") or {},
        "root_cause_hypotheses": rows,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "dependency_install_attempted": False,
        "detector_tuning_performed": False,
        "thresholds_weakened": False,
        "report_ready_created": False,
        "counts_as_finding": False,
        "production_readiness_changed": False,
        "counts_toward_readiness": False,
    }
    scoring = root / "scoring"
    scoring.mkdir(parents=True, exist_ok=True)
    split_name = safe_split_name(split)
    (scoring / f"{split_name}_root_cause_precision_audit.json").write_text(json.dumps(payload, indent=2) + "\n")
    (scoring / "root_cause_hypothesis_generation.json").write_text(json.dumps(payload, indent=2) + "\n")
    return payload


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Generate source-supported post-hoc root-cause hypotheses")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="fresh-confirmation")
    p.add_argument("--frozen-only", action="store_true")
    args = p.parse_args(argv)
    result = run_split(Path(args.root), split=args.split)
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
