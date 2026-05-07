#!/usr/bin/env python3
"""Generate human adjudication packets for fresh holdout expected findings."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from fresh_holdout_scoring import score_split
from frozen_output_loader import PUBLIC_ROOT, load_case_outputs
from proof_of_patch_pair_scorer import score_pairs as score_patched_pairs


def find_item_by_id(items: list[dict[str, Any]], item_id: str) -> dict[str, Any] | None:
    for item in items:
        if item_id and item_id in {str(item.get("id")), str(item.get("lead_id")), str(item.get("queue_id"))}:
            return item
    return None


def packet_text(case_id: str, miss: dict[str, Any], related_hyp: dict[str, Any] | None, related_manual: dict[str, Any] | None) -> str:
    hyp_score = related_hyp.get("quality_score", "not scored") if related_hyp else "N/A"
    return f"""# Fresh Holdout Adjudication Packet: {case_id} / {miss.get('expected_finding_id')}

## Expected Finding
- Title: {miss.get('expected_title')}
- Severity: {miss.get('expected_severity')}
- Component: {miss.get('expected_component')}
- Function: {miss.get('expected_function')}

## Generated Related Confirmed Finding
None. No REPORT_READY finding was generated.

## Generated Related Hypothesis
```json
{json.dumps(related_hyp or {}, indent=2)}
```

## Generated Manual Review Item
```json
{json.dumps(related_manual or {}, indent=2)}
```

## Match Assessment
- Match type: {miss.get('match_type')}
- Miss category: {miss.get('miss_category')}
- Report quality score: 0
- Hypothesis quality score: {hyp_score}
- Human adjudication required: {miss.get('requires_human_adjudication')}

## Missing Evidence
{chr(10).join('- ' + e for e in miss.get('evidence_missing', []))}

## Reviewer Questions
- Did the agent identify the same root cause?
- Did it identify the correct component or lifecycle?
- Did it describe a realistic exploit path?
- Did it identify the asset at risk?
- Would this hypothesis help a human bounty hunter?
- Is the link only broad/category-level?
- What evidence is missing to make it report-ready?
- What PoC would confirm or kill the hypothesis?
"""


def patched_packet_text(pair: dict[str, Any]) -> str:
    return f"""# Proof-of-Patch Patched-Control Adjudication Packet: {pair.get('pair_id')}

## Pair Versions
- Vulnerable case: {pair.get('vulnerable_case_id')}
- Patched case: {pair.get('patched_case_id')}

## Frozen Detection Summary
- Vulnerable lead count: {pair.get('vulnerable_lead_count')}
- Patched lead count: {pair.get('patched_lead_count')}
- Vulnerable related lead: {pair.get('vulnerable_related_lead')}
- Vulnerable report-ready finding: {pair.get('vulnerable_report_ready')}
- Patched original bug suppressed: {pair.get('patched_original_bug_suppressed')}
- Patched report-ready false positive: {pair.get('false_positive')}

## Metadata Isolation
- Metadata used after freeze only: {pair.get('metadata_used_after_freeze_only')}
- Detection metadata access: false

## Reviewer Questions
- Did the vulnerable source generate a lead related to the post-freeze metadata label?
- Did the patched source suppress the original bug without creating a report-ready false positive?
- Are any remaining patched leads only hypotheses/manual-review items rather than findings?
"""


def generate_patched_packets(root: Path = PUBLIC_ROOT, *, split: str = "patched-controls") -> dict[str, Any]:
    score = score_patched_pairs(root, split=split)
    packet_rows = []
    for pair in score.get("pairs", []):
        if pair.get("status") != "PASS":
            continue
        out_dir = root / "adjudication" / split
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / f"{pair.get('pair_id')}.md"
        out.write_text(patched_packet_text(pair))
        packet_rows.append({"packet": out.relative_to(root).as_posix(), "pair_id": pair.get("pair_id"), "created": True, "needs_human_review": True, "reason": "patched-control relatedness/suppression requires human review"})
    result = {"status": "PASS" if packet_rows else "BLOCKED", "split": split, "packet_count": len(packet_rows), "packets": packet_rows}
    (root / "scoring" / "patched_control_adjudication_packets.json").parent.mkdir(parents=True, exist_ok=True)
    (root / "scoring" / "patched_control_adjudication_packets.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def generate_packets(root: Path = PUBLIC_ROOT, *, split: str = "fresh-holdout") -> dict[str, Any]:
    if split == "patched-controls":
        return generate_patched_packets(root, split=split)
    score = score_split(root, split=split, frozen_only=True)
    packet_rows = []
    for case in score.get("cases", []):
        case_id = case["case_id"]
        loaded = load_case_outputs(root, case_id)
        hyps = loaded.get("artifacts", {}).get("hypotheses", {}).get("hypotheses", [])
        manuals = loaded.get("artifacts", {}).get("manual_review_queue", {}).get("items", [])
        quality_by_id = {q["hypothesis_id"]: q for q in case.get("hypothesis_quality", [])}
        for miss in case.get("miss_rows", []):
            related = find_item_by_id(hyps, miss.get("related_hypothesis_id", ""))
            if related:
                related = dict(related, **quality_by_id.get(related.get("id") or related.get("lead_id"), {}))
            manual = find_item_by_id(manuals, miss.get("related_hypothesis_id", ""))
            out_dir = root / "adjudication" / split / case_id
            out_dir.mkdir(parents=True, exist_ok=True)
            out = out_dir / f"{miss.get('expected_finding_id')}.md"
            out.write_text(packet_text(case_id, miss, related, manual))
            packet_rows.append({"packet": out.relative_to(root).as_posix(), "case_id": case_id, "expected_finding_id": miss.get("expected_finding_id"), "created": True, "needs_human_review": True, "reason": "strict/semantic validation requires human adjudication"})
    result = {"status": "PASS" if packet_rows else "BLOCKED", "split": split, "packet_count": len(packet_rows), "packets": packet_rows}
    (root / "scoring" / "fresh_adjudication_packets.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Generate fresh-holdout adjudication packets")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="fresh-holdout")
    p.add_argument("--frozen-only", action="store_true")
    args = p.parse_args(argv)
    result = generate_packets(Path(args.root), split=args.split)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
