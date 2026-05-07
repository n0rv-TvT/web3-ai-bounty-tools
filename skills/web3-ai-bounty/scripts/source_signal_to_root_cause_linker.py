#!/usr/bin/env python3
"""Link frozen source signals to root-cause-specific repair rows."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT
from root_cause_hypothesis_generator import generate_root_cause_hypothesis, load_hypotheses, run_split as generate_root_causes, safe_split_name
from source_fact_to_attack_story_linker import source_reasons


def link_source_signal_to_root_cause(h: dict[str, Any], *, match: dict[str, Any] | None = None) -> dict[str, Any]:
    reasons = source_reasons(h)
    has_signal = bool(h.get("external_evidence") or h.get("code_path") or reasons)
    generated = generate_root_cause_hypothesis(h, match=match)
    root_cause = str(generated.get("root_cause_hypothesis") or "")
    linked = bool(has_signal and generated.get("status") == "PASS" and root_cause)
    return {
        "status": "PASS" if linked else "BLOCKED",
        "hypothesis_id": generated.get("hypothesis_id"),
        "case_id": generated.get("case_id"),
        "source_signal_present": has_signal,
        "source_reasons": reasons,
        "exact_location": bool(generated.get("file_path") and generated.get("contract") and generated.get("function")),
        "file_path": generated.get("file_path"),
        "contract": generated.get("contract"),
        "function": generated.get("function"),
        "root_cause_hypothesis": root_cause,
        "expected_finding_related": bool(generated.get("expected_finding_related")),
        "match_type": generated.get("match_type", "none"),
        "link_status": "SOURCE_SIGNAL_LINKED_TO_ROOT_CAUSE" if linked else "SOURCE_SIGNAL_NOT_LINKED_TO_ROOT_CAUSE",
        "answer_key_text_dependency": False,
        "counts_toward_readiness": False,
    }


def run_split(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation") -> dict[str, Any]:
    root_cause_payload = generate_root_causes(root, split=split)
    matches = {
        str(row.get("hypothesis_id")): row
        for row in root_cause_payload.get("root_cause_hypotheses", [])
        if row.get("hypothesis_id")
    }
    rows = [link_source_signal_to_root_cause(h, match=matches.get(str(h.get("id") or h.get("lead_id") or h.get("hypothesis_id") or ""))) for h in load_hypotheses(root, split)]
    payload = {
        "status": "PASS" if rows else "BLOCKED",
        "split": split,
        "classification": "posthoc_source_signal_to_root_cause_linking_only",
        "source_signal_count": sum(1 for row in rows if row.get("source_signal_present")),
        "linked_count": sum(1 for row in rows if row.get("status") == "PASS"),
        "expected_related_linked_count": sum(1 for row in rows if row.get("status") == "PASS" and row.get("expected_finding_related")),
        "links": rows,
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
    (scoring / f"{safe_split_name(split)}_source_signal_to_root_cause_links.json").write_text(json.dumps(payload, indent=2) + "\n")
    (scoring / "source_signal_to_root_cause_links.json").write_text(json.dumps(payload, indent=2) + "\n")
    return payload


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Link source signals to root-cause-specific hypotheses")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="fresh-confirmation")
    p.add_argument("--frozen-only", action="store_true")
    args = p.parse_args(argv)
    result = run_split(Path(args.root), split=args.split)
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
