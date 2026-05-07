#!/usr/bin/env python3
"""Compare frozen vulnerable and patched hypotheses for patched controls."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT, load_case_outputs
from hypothesis_quality_scorer import score_hypothesis
from patch_diff_analyzer import analyze_split as analyze_patch_diff


def load_manifest(root: Path) -> dict[str, Any]:
    path = root / "patched_control_manifest.json"
    return json.loads(path.read_text(errors="replace")) if path.exists() else {"pairs": []}


def load_metadata(root: Path, pair: dict[str, Any]) -> dict[str, Any]:
    path = root / pair.get("metadata_path", "")
    return json.loads(path.read_text(errors="replace")) if path.exists() else {}


def norm(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-")


def token_set(*values: Any) -> set[str]:
    return {t for v in values for t in re.split(r"[^a-z0-9]+", str(v or "").lower()) if len(t) > 2}


def related_to_metadata(h: dict[str, Any], metadata: dict[str, Any]) -> bool:
    expected = norm(metadata.get("expected_vulnerability"))
    if not expected:
        return False
    text = norm(" ".join(str(h.get(k, "")) for k in ["bug_class", "title", "exploit_scenario", "function", "contract"]))
    return expected in text or expected.replace("-", "") in text.replace("-", "")


def hypothesis_similarity(a: dict[str, Any], b: dict[str, Any]) -> tuple[float, list[str]]:
    evidence = []
    score = 0.0
    if norm(a.get("bug_class")) and norm(a.get("bug_class")) == norm(b.get("bug_class")):
        score += 0.35
        evidence.append("same bug_class")
    if norm(a.get("contract")) and norm(a.get("contract")) == norm(b.get("contract")):
        score += 0.25
        evidence.append("same contract")
    if norm(a.get("function")) and norm(a.get("function")) == norm(b.get("function")):
        score += 0.25
        evidence.append("same function")
    if norm(a.get("file_path")) and norm(a.get("file_path")) == norm(b.get("file_path")):
        score += 0.15
        evidence.append("same file")
    overlap = token_set(a.get("exploit_scenario"), a.get("title")) & token_set(b.get("exploit_scenario"), b.get("title"))
    if len(overlap) >= 4:
        score += 0.15
        evidence.append("overlapping exploit tokens")
    return min(score, 1.0), evidence


def best_match(h: dict[str, Any], candidates: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, float, list[str]]:
    best: tuple[dict[str, Any] | None, float, list[str]] = (None, 0.0, [])
    for candidate in candidates:
        score, evidence = hypothesis_similarity(h, candidate)
        if score > best[1]:
            best = (candidate, score, evidence)
    return best


def classify_vulnerable(h: dict[str, Any], patched_hypotheses: list[dict[str, Any]], metadata: dict[str, Any], diff: dict[str, Any]) -> dict[str, Any]:
    match, similarity, evidence = best_match(h, patched_hypotheses)
    related = related_to_metadata(h, metadata)
    match_quality = score_hypothesis(match) if match else {"overbroad_noise": False}
    if related and diff.get("original_exploit_path_removed") and (similarity < 0.45 or match_quality.get("overbroad_noise")):
        status = "SUPPRESSED_BY_PATCH"
        reason = "related vulnerable hypothesis is absent or only reappears as overbroad patched noise while diff indicates a security-relevant change"
    elif related and similarity >= 0.7:
        status = "STILL_PRESENT_IN_PATCH"
        reason = "related vulnerable hypothesis closely matches a patched hypothesis"
    elif related and 0.45 <= similarity < 0.7:
        status = "MUTATED_IN_PATCH"
        reason = "related vulnerable hypothesis has a partial patched match"
    elif not related:
        status = "UNRELATED_TO_PATCH"
        reason = "vulnerable hypothesis does not match the original post-freeze metadata label"
    elif similarity < 0.45:
        status = "NO_MATCH_IN_PATCH"
        reason = "related vulnerable hypothesis has no close patched-side match, but patch removal is not proven"
    else:
        status = "UNKNOWN"
        reason = "insufficient evidence for suppression or persistence"
    return {
        "vulnerable_hypothesis_id": h.get("id") or h.get("lead_id"),
        "patched_match_id": (match or {}).get("id") or (match or {}).get("lead_id"),
        "patched_match_status": status,
        "comparison_reason": reason,
        "evidence": evidence + (["metadata-related"] if related else []),
        "confidence": round(max(similarity, float(diff.get("patch_confidence") or 0.0) if status == "SUPPRESSED_BY_PATCH" else similarity), 2),
        "counts_as_finding": False,
        "report_ready": False,
    }


def classify_patched(h: dict[str, Any], vulnerable_hypotheses: list[dict[str, Any]], metadata: dict[str, Any]) -> dict[str, Any]:
    match, similarity, evidence = best_match(h, vulnerable_hypotheses)
    quality = score_hypothesis(h)
    if quality["overbroad_noise"]:
        status = "OVERBROAD_NOISE"
        reason = "patched hypothesis lacks enough precision for useful confirmation"
    elif related_to_metadata(h, metadata) and similarity >= 0.45:
        status = "ORIGINAL_BUG_FALSE_POSITIVE"
        reason = "patched hypothesis still resembles the original metadata-labeled bug"
    elif quality["high_quality"]:
        status = "VALID_RESIDUAL_RISK"
        reason = "patched hypothesis is high quality but unrelated to the original bug"
    elif similarity < 0.45:
        status = "UNRELATED_RESIDUAL_HYPOTHESIS"
        reason = "patched hypothesis does not closely match vulnerable original-bug hypotheses"
    else:
        status = "UNKNOWN"
        reason = "patched hypothesis needs human review"
    return {
        "patched_hypothesis_id": h.get("id") or h.get("lead_id"),
        "vulnerable_match_id": (match or {}).get("id") or (match or {}).get("lead_id"),
        "patched_hypothesis_classification": status,
        "comparison_reason": reason,
        "quality_score": quality["quality_score"],
        "evidence": evidence,
        "confidence": round(max(similarity, quality["quality_score"] / 10.0), 2),
        "counts_as_finding": False,
        "report_ready": False,
    }


def require_frozen(root: Path, pair: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    vuln = load_case_outputs(root, pair["vulnerable_case_id"])
    patched = load_case_outputs(root, pair["patched_case_id"])
    blocks = []
    if vuln["status"] != "PASS":
        blocks.append("vulnerable frozen outputs missing")
    if patched["status"] != "PASS":
        blocks.append("patched frozen outputs missing")
    return vuln, patched, blocks


def compare_pair(root: Path, pair: dict[str, Any], diff_by_pair: dict[str, dict[str, Any]]) -> dict[str, Any]:
    vuln, patched, blocks = require_frozen(root, pair)
    if blocks:
        return {"pair_id": pair.get("pair_id"), "status": "BLOCKED", "reason": "frozen outputs required", "blocks": blocks}
    metadata = load_metadata(root, pair)
    vuln_h = vuln["artifacts"]["hypotheses"].get("hypotheses", [])
    patched_h = patched["artifacts"]["hypotheses"].get("hypotheses", [])
    diff = diff_by_pair.get(pair["pair_id"], {})
    vulnerable_rows = [classify_vulnerable(h, patched_h, metadata, diff) for h in vuln_h]
    patched_rows = [classify_patched(h, vuln_h, metadata) for h in patched_h]
    original_status = "SUPPRESSED_BY_PATCH" if any(r["patched_match_status"] == "SUPPRESSED_BY_PATCH" for r in vulnerable_rows) else ("STILL_PRESENT_IN_PATCH" if any(r["patched_match_status"] == "STILL_PRESENT_IN_PATCH" for r in vulnerable_rows) else "UNKNOWN")
    return {
        "pair_id": pair["pair_id"],
        "status": "PASS",
        "original_bug_status_in_patched_version": original_status,
        "vulnerable_hypothesis_comparisons": vulnerable_rows,
        "patched_hypothesis_classifications": patched_rows,
        "patched_original_bug_still_present": original_status == "STILL_PRESENT_IN_PATCH" or any(r["patched_hypothesis_classification"] == "ORIGINAL_BUG_FALSE_POSITIVE" for r in patched_rows),
        "patched_overbroad_noise_count": sum(1 for r in patched_rows if r["patched_hypothesis_classification"] == "OVERBROAD_NOISE"),
        "patched_valid_residual_risk_count": sum(1 for r in patched_rows if r["patched_hypothesis_classification"] == "VALID_RESIDUAL_RISK"),
        "patched_unrelated_residual_count": sum(1 for r in patched_rows if r["patched_hypothesis_classification"] == "UNRELATED_RESIDUAL_HYPOTHESIS"),
        "metadata_used_after_freeze_only": True,
        "counts_as_finding": False,
        "report_ready": False,
    }


def compare_split(root: Path = PUBLIC_ROOT, *, split: str = "patched-controls") -> dict[str, Any]:
    manifest = load_manifest(root)
    diff = analyze_patch_diff(root, split=split)
    diff_by_pair = {row["pair_id"]: row for row in diff.get("pairs", [])}
    rows = [compare_pair(root, pair, diff_by_pair) for pair in manifest.get("pairs", [])]
    result = {
        "status": "PASS" if rows and all(r["status"] == "PASS" for r in rows) else "BLOCKED",
        "split": split,
        "pair_count": len(rows),
        "patched_original_bug_still_present_count": sum(1 for r in rows if r.get("patched_original_bug_still_present")),
        "patched_overbroad_noise_count": sum(int(r.get("patched_overbroad_noise_count") or 0) for r in rows),
        "patched_valid_residual_risk_count": sum(int(r.get("patched_valid_residual_risk_count") or 0) for r in rows),
        "metadata_used_after_freeze_only": True,
        "pairs": rows,
    }
    out = root / "scoring" / "vulnerable_patched_comparison.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Compare vulnerable and patched frozen hypotheses")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="patched-controls")
    p.add_argument("--frozen-only", action="store_true")
    args = p.parse_args(argv)
    result = compare_split(Path(args.root), split=args.split)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
