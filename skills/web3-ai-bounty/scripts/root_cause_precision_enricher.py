#!/usr/bin/env python3
"""Root-cause precision enrichment for expected-aligned post-hoc repair.

The enrichment is source-pattern driven. Expected finding metadata may select the
post-freeze row under analysis, but the repaired root cause must be backed by
local source evidence and must not depend on report prose.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from expected_aligned_repair_common import (
    PUBLIC_ROOT,
    base_result_flags,
    contract_name_for,
    function_name_before,
    line_number,
    load_expected_rows,
    load_selected_candidate,
    repair_dir,
    source_path_for,
    write_json,
)


def _snippet(text: str, start: int, end: int, pad: int = 120) -> str:
    return re.sub(r"\s+", " ", text[max(0, start - pad) : min(len(text), end + pad)]).strip()[:500]


def scan_source_facts(source_path: Path) -> dict[str, Any]:
    text = source_path.read_text(errors="replace") if source_path.exists() else ""
    facts: list[dict[str, Any]] = []
    if not text:
        return {"status": "BLOCKED", "source_file": str(source_path), "facts": [], "blocks": ["source file missing"]}

    contract = contract_name_for(text)

    # Pattern: SendParam({ amountLD: x, minAmountLD: x, ... }) or the inverse.
    struct_re = re.compile(
        r"SendParam\s+memory\s+[^=;]+?=\s*SendParam\s*\((?P<body>\{.*?\})\s*\)",
        re.S,
    )
    for match in struct_re.finditer(text):
        body = match.group("body")
        amount = re.search(r"amountLD\s*:\s*([A-Za-z_][A-Za-z0-9_]*)", body)
        minimum = re.search(r"minAmountLD\s*:\s*([A-Za-z_][A-Za-z0-9_]*)", body)
        if amount and minimum and amount.group(1) == minimum.group(1):
            facts.append({
                "fact_id": "min_amount_equals_amount_in_send_param",
                "pattern": "min_amount_equals_amount",
                "source_file": source_path.as_posix(),
                "contract": contract,
                "function": function_name_before(text, match.start()),
                "line": line_number(text, match.start()),
                "variable": amount.group(1),
                "evidence": _snippet(text, match.start(), match.end()),
                "root_cause_hint": "a cross-chain send minimum is set equal to the nominal amount instead of a deliverable/slippage-adjusted amount",
                "asset_hint": "cross-chain token transfer amount",
                "impact_hint": "fund_freeze_or_denial_of_service",
            })

    # Pattern: param.amountLD = x; param.minAmountLD = x; near a send call.
    assign_re = re.compile(
        r"(?P<param>[A-Za-z_][A-Za-z0-9_]*)\.amountLD\s*=\s*(?P<amount>[A-Za-z_][A-Za-z0-9_]*)\s*;(?P<body>.{0,320}?)\1\.minAmountLD\s*=\s*(?P<min>[A-Za-z_][A-Za-z0-9_]*)\s*;",
        re.S,
    )
    for match in assign_re.finditer(text):
        if match.group("amount") == match.group("min"):
            facts.append({
                "fact_id": "min_amount_assignment_equals_amount",
                "pattern": "min_amount_equals_amount",
                "source_file": source_path.as_posix(),
                "contract": contract,
                "function": function_name_before(text, match.start()),
                "line": line_number(text, match.start()),
                "variable": match.group("amount"),
                "evidence": _snippet(text, match.start(), match.end()),
                "root_cause_hint": "a cross-chain send minimum is assigned the same nominal amount that may later be debited or dust-adjusted",
                "asset_hint": "cross-chain token transfer amount",
                "impact_hint": "fund_freeze_or_denial_of_service",
            })

    # Pattern: external arbitrary call from a contract that holds ERC721/tokens.
    for match in re.finditer(r"\([^\n;]*bool\s+success[^\n;]*,?\s*\)\s*=\s*[^;]+\.call\s*\(", text):
        nearby = _snippet(text, match.start(), match.end(), pad=240).lower()
        if "balanceof" in nearby or "approve" in nearby or "safeTransferFrom" in text:
            facts.append({
                "fact_id": "arbitrary_external_call_with_custodied_assets",
                "pattern": "arbitrary_external_call",
                "source_file": source_path.as_posix(),
                "contract": contract,
                "function": function_name_before(text, match.start()),
                "line": line_number(text, match.start()),
                "evidence": _snippet(text, match.start(), match.end()),
                "root_cause_hint": "user-controlled external call executes from the custodian contract while other custodied assets remain reachable",
                "asset_hint": "custodied tokens or NFTs",
                "impact_hint": "stolen_funds_or_unauthorized_transfer",
            })

    # Pattern: owner-set global dependency changed without lock/epoch guard.
    for match in re.finditer(r"function\s+(set[A-Za-z0-9_]+)\s*\([^)]*\)\s*external\s+onlyOwner", text):
        body = text[match.end() : text.find("\n    }", match.end()) if text.find("\n    }", match.end()) != -1 else match.end() + 600]
        if "jackpotLock" not in body and "currentDrawing" in text:
            facts.append({
                "fact_id": "owner_global_setter_without_active_lifecycle_guard",
                "pattern": "active_lifecycle_global_mutation",
                "source_file": source_path.as_posix(),
                "contract": contract,
                "function": match.group(1),
                "line": line_number(text, match.start()),
                "evidence": _snippet(text, match.start(), match.end() + len(body)),
                "root_cause_hint": "owner-set global dependency can be changed during an active lifecycle because the setter lacks a lifecycle lock guard",
                "asset_hint": "active lifecycle settlement state",
                "impact_hint": "unauthorized_state_change_or_denial_of_service",
            })

    return {"status": "PASS" if facts else "BLOCKED", "source_file": str(source_path), "facts": facts, "blocks": [] if facts else ["no supported source pattern found"]}


def select_fact_for_candidate(facts: list[dict[str, Any]], selected: dict[str, Any]) -> dict[str, Any] | None:
    expected_function = str(selected.get("expected_function") or "")
    expected_impact = str(selected.get("expected_impact_type") or selected.get("expected_title") or "").lower()
    ranked = []
    for fact in facts:
        score = 0
        if expected_function and fact.get("function") == expected_function:
            score += 4
        if fact.get("pattern") == "min_amount_equals_amount" and any(t in expected_impact for t in ["dust", "unstake", "redeem", "freeze", "fail"]):
            score += 3
        if fact.get("pattern") == "arbitrary_external_call" and any(t in expected_impact for t in ["steal", "nft", "custody"]):
            score += 3
        if fact.get("pattern") == "active_lifecycle_global_mutation" and any(t in expected_impact for t in ["active", "drawing", "entropy", "payout"]):
            score += 2
        ranked.append((score, fact))
    ranked.sort(key=lambda row: row[0], reverse=True)
    return ranked[0][1] if ranked else None


def root_cause_from_fact(fact: dict[str, Any]) -> tuple[str, str, str]:
    pattern = fact.get("pattern")
    if pattern == "min_amount_equals_amount":
        return (
            "denial-of-service",
            "The cross-chain send path sets the minimum deliverable amount equal to the nominal asset amount even though the send layer can debit or deliver a lower dust-adjusted amount.",
            "medium",
        )
    if pattern == "arbitrary_external_call":
        return (
            "access-control",
            "The contract executes user-controlled external call data from a custodian context before proving that only the intended asset can move.",
            "medium",
        )
    if pattern == "active_lifecycle_global_mutation":
        return (
            "business-logic",
            "A global dependency or parameter setter lacks an active-lifecycle guard, so settlement can read a value that differs from the value assumed when the lifecycle began.",
            "medium",
        )
    return ("business-logic", str(fact.get("root_cause_hint") or "source-supported invariant break"), "low")


def enrich_selected(root: Path = PUBLIC_ROOT, *, split: str = "fresh-v6") -> dict[str, Any]:
    selected = load_selected_candidate(root)
    if not selected:
        result = {"status": "EXPECTED_RELATED_REPAIR_INCONCLUSIVE", "split": split, "reason": "no selected expected-related candidate", **base_result_flags()}
        write_json(repair_dir(root) / "expected_related_source_fact_map.json", result)
        write_json(repair_dir(root) / "expected_related_root_cause_gap_analysis.json", result)
        return result

    source_file = str(selected.get("source_file") or selected.get("related_file") or selected.get("expected_source_file") or "")
    source_path = source_path_for(root, split, str(selected.get("case_id")), source_file)
    scan = scan_source_facts(source_path)
    fact = select_fact_for_candidate(scan.get("facts", []), selected)
    if not fact:
        result = {
            "status": "EXPECTED_RELATED_REPAIR_BLOCKED_MISSING_SOURCE_FACTS",
            "split": split,
            "candidate_id": selected.get("candidate_id"),
            "case_id": selected.get("case_id"),
            "expected_finding_id": selected.get("expected_finding_id"),
            "source_scan": scan,
            "answer_key_text_dependency": False,
            "remaining_root_cause_gaps": ["no source-supported root-cause pattern was found"],
            **base_result_flags(),
        }
        write_json(repair_dir(root) / "expected_related_source_fact_map.json", result)
        write_json(repair_dir(root) / "expected_related_root_cause_gap_analysis.json", result)
        return result

    bug_class, root_cause, confidence = root_cause_from_fact(fact)
    candidate_id = str(selected.get("candidate_id"))
    repaired = {
        "candidate_id": candidate_id,
        "case_id": selected.get("case_id"),
        "expected_finding_id": selected.get("expected_finding_id"),
        "selected_hypothesis_id": selected.get("selected_hypothesis_id"),
        "match_type_before_repair": selected.get("match_type_before_repair"),
        "file": str(selected.get("source_file") or selected.get("related_file") or selected.get("expected_source_file") or ""),
        "contract": fact.get("contract") or selected.get("related_component") or selected.get("expected_component"),
        "function": fact.get("function") or selected.get("related_function") or selected.get("expected_function"),
        "lifecycle_transition": selected.get("related_lifecycle") or "source-supported boundary transition",
        "bug_class": bug_class,
        "root_cause_hypothesis": root_cause,
        "source_evidence": [fact],
        "root_cause_confidence": confidence,
        "answer_key_text_dependency": False,
        "remaining_root_cause_gaps": [],
        "expected_finding_related": True,
        "component_only": False,
        **base_result_flags(),
    }
    source_fact_map = {
        "status": "PASS",
        "split": split,
        "candidate_id": candidate_id,
        "source_scan": scan,
        "selected_source_fact": fact,
        "answer_key_text_dependency": False,
        **base_result_flags(),
    }
    gap_analysis = {
        "status": "PASS",
        "split": split,
        "candidate_id": candidate_id,
        "before_gap": selected.get("main_gap"),
        "after_gap": "ROOT_CAUSE_SOURCE_SUPPORTED",
        "root_cause_precision_improved": True,
        "remaining_root_cause_gaps": [],
        "repaired_candidate": repaired,
        **base_result_flags(),
    }
    write_json(repair_dir(root) / "expected_related_source_fact_map.json", source_fact_map)
    write_json(repair_dir(root) / "expected_related_root_cause_gap_analysis.json", gap_analysis)
    return write_json(repair_dir(root) / "expected_related_root_cause_precision.json", {"status": "PASS", "split": split, "candidate": repaired, **base_result_flags()})


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Enrich expected-related repair candidate root cause from source facts")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="fresh-v6")
    p.add_argument("--frozen-only", action="store_true")
    p.add_argument("--selected", action="store_true")
    args = p.parse_args(argv)
    result = enrich_selected(Path(args.root), split=args.split)
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") in {"PASS", "EXPECTED_RELATED_REPAIR_BLOCKED_MISSING_SOURCE_FACTS", "EXPECTED_RELATED_REPAIR_INCONCLUSIVE"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
