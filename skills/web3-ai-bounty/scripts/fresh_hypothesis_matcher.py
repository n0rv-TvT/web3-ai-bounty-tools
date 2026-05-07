#!/usr/bin/env python3
"""Match fresh expected findings to frozen hypotheses/manual-review items."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

STOP = {"the", "and", "or", "of", "in", "to", "for", "by", "a", "an", "can", "be", "is", "with", "when", "from", "not", "does", "will", "may", "into", "due", "as", "on"}


def tokens(value: Any) -> set[str]:
    text = str(value or "").lower()
    return {t for t in re.split(r"[^a-z0-9_]+", text) if len(t) > 2 and t not in STOP}


def norm_bug(value: str) -> str:
    value = (value or "").lower().replace("_", "-")
    aliases = {
        "decimal-accounting": "accounting-desync",
        "oracle-accounting": "oracle-manipulation",
        "oracle-staleness": "oracle-manipulation",
        "eth-transfer": "denial-of-service",
        "math-convergence": "business-logic",
        "invalid-validation": "business-logic",
        "overflow": "arithmetic",
        "denial-of-service": "business-logic",
        "reentrancy-or-availability": "reentrancy-or-stale-accounting",
    }
    return aliases.get(value, value)


def fields_for_generated(item: dict[str, Any]) -> dict[str, str]:
    return {
        "id": str(item.get("id") or item.get("lead_id") or item.get("queue_id") or ""),
        "title": str(item.get("title") or item.get("review_goal") or ""),
        "bug_class": str(item.get("bug_class") or ""),
        "file": str(item.get("file_path") or item.get("file") or ""),
        "contract": str(item.get("contract") or ""),
        "function": str(item.get("function") or ""),
        "impact": str((item.get("impact") or {}).get("type") if isinstance(item.get("impact"), dict) else item.get("impact_type") or ""),
        "scenario": str(item.get("exploit_scenario") or item.get("review_goal") or ""),
    }


def fields_for_expected(expected: dict[str, Any]) -> dict[str, str]:
    return {
        "id": str(expected.get("finding_id") or ""),
        "title": str(expected.get("title") or ""),
        "bug_class": str(expected.get("bug_class") or ""),
        "file": str(expected.get("source_file") or expected.get("expected_component") or ""),
        "contract": str(expected.get("affected_contract") or ""),
        "function": str(expected.get("affected_function") or ""),
        "impact": str(expected.get("impact_type") or ""),
        "root": str(expected.get("root_cause") or expected.get("root_cause_rule") or ""),
    }


def overlap(a: str, b: str) -> int:
    return len(tokens(a) & tokens(b))


def classify_match(expected: dict[str, Any], generated: dict[str, Any]) -> dict[str, Any]:
    exp = fields_for_expected(expected)
    gen = fields_for_generated(generated)
    bug_match = norm_bug(exp["bug_class"]) == norm_bug(gen["bug_class"])
    same_contract = bool(exp["contract"] and gen["contract"] and exp["contract"].lower() == gen["contract"].lower())
    same_function = bool(exp["function"] and gen["function"] and exp["function"].lower() == gen["function"].lower())
    file_overlap = bool(exp["file"] and gen["file"] and (Path(exp["file"]).name.lower() == Path(gen["file"]).name.lower() or exp["file"].lower() in gen["file"].lower() or gen["file"].lower() in exp["file"].lower()))
    root_overlap = overlap(exp["root"], gen["scenario"] + " " + gen["title"])
    impact_overlap = bool(tokens(exp["impact"]) & tokens(gen["impact"] + " " + gen["scenario"]))
    title_overlap = overlap(exp["title"], gen["title"] + " " + gen["scenario"])
    matched_fields = []
    if bug_match:
        matched_fields.append("bug_class")
    if same_contract:
        matched_fields.append("contract")
    if same_function:
        matched_fields.append("function")
    if file_overlap:
        matched_fields.append("file")
    if root_overlap >= 2:
        matched_fields.append("root_cause")
    if impact_overlap:
        matched_fields.append("impact")
    if title_overlap >= 2:
        matched_fields.append("title_terms")

    strict = bug_match and (same_contract or file_overlap) and same_function and root_overlap >= 2 and impact_overlap
    semantic = not strict and bug_match and root_overlap >= 2 and impact_overlap and (same_contract or file_overlap or same_function)
    # Weak is intentionally component/entrypoint-level only. Category-only or
    # title-term-only similarity is too broad and must remain no_match.
    weak = not strict and not semantic and (same_contract or same_function or file_overlap)
    if strict:
        level = "strict"
    elif semantic:
        level = "semantic"
    elif weak:
        level = "weak"
    else:
        level = "none"
    return {
        "match_type": level,
        "strict_match": strict,
        "semantic_match": semantic,
        "weak_match": weak,
        "generated_id": gen["id"],
        "matched_fields": matched_fields,
        "score": len(matched_fields) + (2 if strict else 1 if semantic else 0),
        "requires_human_adjudication": level in {"semantic", "weak"},
    }


def best_match(expected: dict[str, Any], generated_items: list[dict[str, Any]]) -> dict[str, Any]:
    if not generated_items:
        return {"match_type": "none", "strict_match": False, "semantic_match": False, "weak_match": False, "generated_id": "", "matched_fields": [], "score": 0, "requires_human_adjudication": False}
    ranked = [classify_match(expected, item) | {"generated_item": item} for item in generated_items]
    order = {"strict": 4, "semantic": 3, "weak": 2, "none": 1}
    ranked.sort(key=lambda r: (order[r["match_type"]], r["score"]), reverse=True)
    best = ranked[0]
    return {k: v for k, v in best.items() if k != "generated_item"}


def match_expected_set(expected_rows: list[dict[str, Any]], generated_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for expected in expected_rows:
        match = best_match(expected, generated_items)
        out.append({"case_id": expected.get("case_id"), "expected_finding_id": expected.get("finding_id"), "expected_title": expected.get("title"), **match})
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Match expected fresh findings to generated hypotheses")
    p.add_argument("expected_json")
    p.add_argument("generated_json")
    args = p.parse_args(argv)
    expected_payload = json.loads(Path(args.expected_json).read_text(errors="replace"))
    generated_payload = json.loads(Path(args.generated_json).read_text(errors="replace"))
    expected_rows = expected_payload.get("all_expected_findings", [])
    generated_items = generated_payload.get("hypotheses") or generated_payload.get("items") or generated_payload.get("findings") or []
    print(json.dumps({"matches": match_expected_set(expected_rows, generated_items)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
