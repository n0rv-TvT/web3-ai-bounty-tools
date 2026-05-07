#!/usr/bin/env python3
"""Resolve concrete affected asset/state and impact class for repaired leads."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT
from root_cause_hypothesis_generator import load_hypotheses, run_split as generate_root_causes, safe_split_name
from source_fact_to_attack_story_linker import asset_from_facts


def run_selected(root: Path = PUBLIC_ROOT, *, split: str = "fresh-v6") -> dict[str, Any]:
    from expected_aligned_repair_common import base_result_flags, load_json, repair_dir, write_json

    root_cause_payload = load_json(repair_dir(root) / "expected_related_root_cause_precision.json", {})
    root_cause = root_cause_payload.get("candidate") or {}
    if not root_cause:
        result = {"status": "EXPECTED_RELATED_REPAIR_BLOCKED_MISSING_ASSET_IMPACT", "split": split, "reason": "missing root-cause candidate", **base_result_flags()}
        return write_json(repair_dir(root) / "expected_related_asset_impact.json", result)

    evidence = (root_cause.get("source_evidence") or [{}])[0]
    impact_hint = str(evidence.get("impact_hint") or "").replace("_", "-")
    asset = evidence.get("asset_hint") or root_cause.get("affected_asset") or root_cause.get("lifecycle_transition") or "affected asset/state"
    condition = " ".join(
        str(part or "")
        for part in [
            root_cause.get("root_cause_hypothesis"),
            evidence.get("root_cause_hint"),
            evidence.get("pattern"),
        ]
    ).strip()
    result = {
        "status": "PASS" if asset and condition else "EXPECTED_RELATED_REPAIR_BLOCKED_MISSING_ASSET_IMPACT",
        "split": split,
        "candidate_id": root_cause.get("candidate_id"),
        "case_id": root_cause.get("case_id"),
        "expected_finding_id": root_cause.get("expected_finding_id"),
        "affected_asset": asset,
        "impact_type": impact_hint or impact_type_for(root_cause, str(root_cause.get("root_cause_hypothesis") or "")),
        "impact_condition": condition,
        "answer_key_text_dependency": False,
        **base_result_flags(),
    }
    return write_json(repair_dir(root) / "expected_related_asset_impact.json", result)


GENERIC_MARKERS = ["requires validation", "protocol-controlled assets", "unknown", "exact asset"]


def is_concrete_asset(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and not any(marker in text for marker in GENERIC_MARKERS)


def impact_type_for(h: dict[str, Any], root_cause: str = "") -> str:
    impact = h.get("impact") if isinstance(h.get("impact"), dict) else {}
    text = " ".join([str(impact.get("type") or h.get("impact_type") or ""), str(h.get("bug_class") or ""), root_cause]).lower()
    if any(token in text for token in ["unauthorized", "access", "privileged", "role"]):
        return "unauthorized-privileged-action"
    if any(token in text for token in ["oracle", "price", "debt", "collateral"]):
        return "bad-debt-or-bad-pricing"
    if any(token in text for token in ["freeze", "frozen", "denial", "availability", "blocked", "dos"]):
        return "frozen-funds-or-availability"
    if any(token in text for token in ["signature", "replay", "nonce", "domain"]):
        return "unauthorized-privileged-action"
    if any(token in text for token in ["stolen", "loss", "drain", "inflation", "accounting", "shares"]):
        return "stolen-funds-or-user-loss"
    return "accepted-impact-requires-manual-confirmation"


def resolve_asset_impact(h: dict[str, Any], *, root_row: dict[str, Any] | None = None) -> dict[str, Any]:
    root_row = root_row or {}
    impact = h.get("impact") if isinstance(h.get("impact"), dict) else {}
    current_asset = h.get("affected_asset") or impact.get("asset")
    asset = current_asset if is_concrete_asset(current_asset) else root_row.get("affected_asset_hint") or asset_from_facts(h)
    has_location_context = bool(root_row.get("contract") or h.get("contract"))
    concrete = is_concrete_asset(asset) and has_location_context
    root_cause = str(root_row.get("root_cause_hypothesis") or "")
    return {
        "status": "PASS" if concrete else "BLOCKED_MISSING_CONCRETE_ASSET",
        "hypothesis_id": h.get("id") or h.get("lead_id") or h.get("hypothesis_id"),
        "case_id": h.get("case_id"),
        "file_path": h.get("file_path") or h.get("file"),
        "contract": h.get("contract"),
        "function": h.get("function"),
        "affected_asset": asset if concrete else "",
        "impact_type": impact_type_for(h, root_cause),
        "asset_resolution_source": "existing_hypothesis" if is_concrete_asset(current_asset) else "source_signal_reasoning",
        "expected_finding_related": bool(root_row.get("expected_finding_related")),
        "match_type": root_row.get("match_type", "none"),
        "answer_key_text_dependency": False,
        "report_ready": False,
        "counts_as_finding": False,
        "counts_toward_readiness": False,
    }


def run_split(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation") -> dict[str, Any]:
    roots = generate_root_causes(root, split=split)
    by_hypothesis = {str(row.get("hypothesis_id")): row for row in roots.get("root_cause_hypotheses", [])}
    rows = []
    for h in load_hypotheses(root, split):
        hid = str(h.get("id") or h.get("lead_id") or h.get("hypothesis_id") or "")
        rows.append(resolve_asset_impact(h, root_row=by_hypothesis.get(hid)))
    payload = {
        "status": "PASS" if rows else "BLOCKED",
        "split": split,
        "classification": "posthoc_asset_impact_resolution_only",
        "resolved_count": sum(1 for row in rows if row.get("status") == "PASS"),
        "blocked_count": sum(1 for row in rows if row.get("status") != "PASS"),
        "expected_related_resolved_count": sum(1 for row in rows if row.get("status") == "PASS" and row.get("expected_finding_related")),
        "resolutions": rows,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "dependency_install_attempted": False,
        "detector_tuning_performed": False,
        "thresholds_weakened": False,
        "report_ready_created": False,
        "counts_as_finding": False,
        "counts_toward_readiness": False,
    }
    scoring = root / "scoring"
    scoring.mkdir(parents=True, exist_ok=True)
    (scoring / f"{safe_split_name(split)}_asset_impact_resolution.json").write_text(json.dumps(payload, indent=2) + "\n")
    (scoring / "asset_impact_resolution.json").write_text(json.dumps(payload, indent=2) + "\n")
    return payload


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Resolve affected asset/state for post-hoc repaired hypotheses")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="fresh-confirmation")
    p.add_argument("--frozen-only", action="store_true")
    p.add_argument("--selected", action="store_true", help="resolve the expected-aligned selected candidate")
    args = p.parse_args(argv)
    result = run_selected(Path(args.root), split=args.split) if args.selected else run_split(Path(args.root), split=args.split)
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
