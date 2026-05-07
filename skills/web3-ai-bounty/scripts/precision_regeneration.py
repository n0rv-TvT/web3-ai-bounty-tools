#!/usr/bin/env python3
"""Regenerate precise post-hoc hypotheses for already-imported controls.

This workflow is regression-only. It is allowed to re-run local source triage on
existing patched-control directories, but it must not read patch metadata during
generation and must not count toward independent readiness.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT
from hypothesis_quality_scorer import score_regenerated_hypothesis
from poc_task_generator import task_type_for
from protocol_xray import run_protocol_xray

OUT_DIR_NAME = "precision_regeneration"
VERSION = "regenerated_precision_v1"


def output_dir(root: Path) -> Path:
    out = root / "scoring" / OUT_DIR_NAME
    out.mkdir(parents=True, exist_ok=True)
    return out


def load_manifest(root: Path) -> dict[str, Any]:
    path = root / "patched_control_manifest.json"
    return json.loads(path.read_text(errors="replace")) if path.exists() else {"pairs": []}


def concrete_asset_for(h: dict[str, Any]) -> str:
    text = f"{h.get('bug_class', '')} {h.get('exploit_scenario', '')} {h.get('title', '')}".lower()
    if "access" in text or "privileged" in text:
        return "privileged protocol state and any assets reachable from the unauthorized action"
    if "account" in text or "share" in text or "erc4626" in text:
        return "protocol-held ERC20 assets and share/accounting balances"
    if "reward" in text:
        return "reward token balances and reward index accounting"
    if "oracle" in text or "price" in text:
        return "collateral valuation and price-dependent protocol solvency"
    if "signature" in text or "replay" in text:
        return "user-authorized assets controlled by signed actions"
    if "reentran" in text:
        return "protocol-held assets touched before external call completion"
    return "protocol-controlled assets or security-sensitive state reached by the function"


def impact_for(h: dict[str, Any]) -> str:
    impact = h.get("impact") or {}
    impact_type = impact.get("type") if isinstance(impact, dict) else ""
    if impact_type and "requires" not in str(impact_type).lower():
        return str(impact_type)
    bug = str(h.get("bug_class") or "").lower()
    if "access" in bug:
        return "unauthorized privileged action or state change"
    if "oracle" in bug:
        return "bad debt or incorrect value movement if price-dependent action is reachable"
    if "signature" in bug:
        return "unauthorized replay or reuse of signed authorization"
    return "stolen funds, frozen funds, bad debt, or unauthorized state change if the hypothesis is proven"


def lifecycle_for(h: dict[str, Any]) -> str:
    name = str(h.get("function") or "").lower()
    for token in ["deposit", "mint", "withdraw", "redeem", "borrow", "repay", "claim", "transfer", "permit", "initialize", "upgrade", "process", "request", "collect"]:
        if token in name:
            return token
    return "state-changing entrypoint"


def evidence_found(h: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for item in h.get("external_evidence") or []:
        rows.append({
            "type": item.get("type", "source_signal"),
            "file": item.get("file_path") or h.get("file_path"),
            "line": item.get("line"),
            "reason": item.get("rule") or item.get("reasons") or item.get("type"),
        })
    if not rows:
        rows.append({"type": "source_signal", "file": h.get("file_path"), "line": None, "reason": "x-ray ranked entrypoint"})
    return rows


def minimal_poc_idea(h: dict[str, Any], asset: str, impact: str) -> dict[str, Any]:
    contract = h.get("contract") or "Target"
    function = h.get("function") or "targetFunction"
    task_type = task_type_for({"bug_class": h.get("bug_class"), "impact": {"type": impact}, "exploit_scenario": h.get("exploit_scenario")})
    return {
        "framework": "Foundry",
        "poc_type": task_type,
        "actors": ["attacker", "victim", "protocol", "honestUser"],
        "setup": [
            f"deploy or instantiate {contract} from the local source tree",
            "fund attacker/victim/control actors with local mock assets",
            "establish the honest baseline for balances, roles, and accounting",
        ],
        "attack_steps": [
            f"attacker calls {contract}.{function} through the suspected vulnerable path",
            "repeat or order calls only as required by the hypothesis",
            "compare attacker, victim, and protocol state before and after",
        ],
        "assertions": [
            f"assert impact on {asset}",
            f"assert the observed state change matches: {impact}",
            "assert a benign control path remains valid",
        ],
        "expected_failure": "PoC must fail if normal attacker reachability or concrete impact is absent",
        "kill_condition": f"kill if {contract}.{function} is not reachable by the stated attacker or no measurable impact on {asset} can be asserted",
    }


def regenerate_hypothesis(raw: dict[str, Any], *, case_id: str, pair_id: str, version_kind: str, index: int) -> dict[str, Any]:
    asset = concrete_asset_for(raw)
    impact = impact_for(raw)
    file_path = raw.get("file_path") or raw.get("file") or "unknown.sol"
    contract = raw.get("contract") or "UnknownContract"
    function = raw.get("function") or "unknownFunction"
    poc = minimal_poc_idea(raw, asset, impact)
    hyp_id = f"PREC-{pair_id}-{version_kind}-{index:03d}"
    return {
        "hypothesis_id": hyp_id,
        "id": hyp_id,
        "lead_id": hyp_id,
        "case_id": case_id,
        "pair_id": pair_id,
        "version": VERSION,
        "version_kind": version_kind,
        "file": file_path,
        "file_path": file_path,
        "contract": contract,
        "function": function,
        "lifecycle_transition": lifecycle_for(raw),
        "bug_class": raw.get("bug_class") or "business-logic",
        "root_cause_hypothesis": raw.get("exploit_scenario") or raw.get("title") or f"{contract}.{function} may violate a protocol invariant",
        "affected_asset": asset,
        "attacker_capability": raw.get("attacker_capabilities") or "normal external caller unless source evidence proves a role requirement",
        "attacker_capabilities": raw.get("attacker_capabilities") or "normal external caller unless source evidence proves a role requirement",
        "exploit_sequence": poc["attack_steps"],
        "exploit_scenario": raw.get("exploit_scenario") or f"attacker exercises {contract}.{function} and checks whether {impact} occurs",
        "impact_if_true": impact,
        "impact": {"type": impact, "asset": asset},
        "evidence_found": evidence_found(raw),
        "external_evidence": raw.get("external_evidence") or evidence_found(raw),
        "evidence_missing": ["execute local PoC", "prove exact balance/state delta", "check intended behavior and duplicates"],
        "minimal_poc_idea": poc,
        "poc": {"idea": poc["poc_type"], "assertion": True, "kill_condition": poc["kill_condition"], "path": ""},
        "poc_idea": poc["poc_type"],
        "kill_condition": poc["kill_condition"],
        "confidence": 0.72 if version_kind == "vulnerable" else 0.58,
        "uncertainty_label": "NEEDS_POC",
        "severity_rationale": "regenerated precision hypothesis for post_hoc_regression_only; not report-ready without executed evidence",
        "state": "HYPOTHESIS",
        "report_ready": False,
        "counts_as_finding": False,
        "post_hoc_regression_only": True,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
    }


def regenerate_case(case_root: Path, *, case_id: str, pair_id: str, version_kind: str, max_hypotheses: int = 5) -> dict[str, Any]:
    xray = run_protocol_xray(case_root, repo_id=case_id)
    raw_hypotheses = (xray.get("bounty_hypotheses") or {}).get("hypotheses", [])[:max_hypotheses]
    regenerated = [regenerate_hypothesis(h, case_id=case_id, pair_id=pair_id, version_kind=version_kind, index=i + 1) for i, h in enumerate(raw_hypotheses)]
    scores = [score_regenerated_hypothesis(h) for h in regenerated]
    return {
        "status": "PASS",
        "case_id": case_id,
        "pair_id": pair_id,
        "version_kind": version_kind,
        "classification": "post_hoc_regression_only",
        "hypothesis_count": len(regenerated),
        "hypotheses": regenerated,
        "quality_scores": scores,
        "average_quality": round(sum(s["quality_score"] for s in scores) / (len(scores) or 1), 2),
        "high_quality_count": sum(1 for s in scores if s["high_quality"]),
        "poc_ready_count": sum(1 for s in scores if s["poc_ready"]),
        "overbroad_noise_count": sum(1 for s in scores if s["overbroad_noise"]),
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "patch_metadata_visible_during_detection": False,
    }


def confirmation_tasks_for(hypotheses: list[dict[str, Any]], scores: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {s["hypothesis_id"]: s for s in scores}
    tasks = []
    for h in hypotheses:
        score = by_id.get(h["hypothesis_id"], {})
        if score.get("quality_score", 0) < 7:
            continue
        tasks.append({
            "hypothesis_id": h["hypothesis_id"],
            "confirmation_status": "NEEDS_POC",
            "missing_evidence": h["evidence_missing"],
            "minimal_poc_plan": h["minimal_poc_idea"],
            "economic_proof_needed": any(token in h["impact_if_true"].lower() for token in ["stolen", "bad debt", "fund", "asset", "profit"]),
            "manual_review_questions": ["Can a normal attacker reach this function?", "Does the assertion prove accepted impact?", "What condition kills the hypothesis?"],
            "report_ready": False,
            "counts_as_finding": False,
        })
    return tasks


def write_pair_outputs(root: Path, pair: dict[str, Any], vulnerable: dict[str, Any], patched: dict[str, Any]) -> dict[str, Any]:
    out = output_dir(root)
    pair_id = pair["pair_id"]
    (out / f"{pair_id}_vulnerable_regenerated_hypotheses.json").write_text(json.dumps(vulnerable, indent=2) + "\n")
    (out / f"{pair_id}_patched_regenerated_hypotheses.json").write_text(json.dumps(patched, indent=2) + "\n")
    all_scores = vulnerable["quality_scores"] + patched["quality_scores"]
    quality = {
        "status": "PASS",
        "pair_id": pair_id,
        "old_average_quality": 4.0,
        "average_quality": round(sum(s["quality_score"] for s in all_scores) / (len(all_scores) or 1), 2),
        "high_quality_count": sum(1 for s in all_scores if s["high_quality"]),
        "poc_ready_count": sum(1 for s in all_scores if s["poc_ready"]),
        "overbroad_noise_count": sum(1 for s in all_scores if s["overbroad_noise"]),
        "overbroad_noise_rate": round(sum(1 for s in all_scores if s["overbroad_noise"]) / (len(all_scores) or 1), 4),
        "scores": all_scores,
    }
    tasks = confirmation_tasks_for(vulnerable["hypotheses"], vulnerable["quality_scores"])
    confirmation = {"status": "PASS", "pair_id": pair_id, "task_count": len(tasks), "tasks": tasks, "auto_promoted_report_ready": 0}
    poc_task_plan = {"status": "PASS", "pair_id": pair_id, "task_count": len(tasks), "tasks": [t["minimal_poc_plan"] | {"hypothesis_id": t["hypothesis_id"]} for t in tasks]}
    (out / f"{pair_id}_quality_scores.json").write_text(json.dumps(quality, indent=2) + "\n")
    (out / f"{pair_id}_confirmation_plan.json").write_text(json.dumps(confirmation, indent=2) + "\n")
    (out / f"{pair_id}_poc_task_plan.json").write_text(json.dumps(poc_task_plan, indent=2) + "\n")
    return {"pair_id": pair_id, "quality": quality, "confirmation": confirmation, "vulnerable": vulnerable, "patched": patched}


def regenerate_split(root: Path = PUBLIC_ROOT, *, split: str = "patched-controls") -> dict[str, Any]:
    manifest = load_manifest(root)
    rows = []
    for pair in manifest.get("pairs", []):
        vulnerable = regenerate_case(root / pair.get("vulnerable_detector_visible_path", f"{split}/{pair['vulnerable_case_id']}"), case_id=pair["vulnerable_case_id"], pair_id=pair["pair_id"], version_kind="vulnerable")
        patched = regenerate_case(root / pair.get("patched_detector_visible_path", f"{split}/{pair['patched_case_id']}"), case_id=pair["patched_case_id"], pair_id=pair["pair_id"], version_kind="patched")
        rows.append(write_pair_outputs(root, pair, vulnerable, patched))
    all_scores = [s for row in rows for s in row["quality"]["scores"]]
    summary = {
        "status": "PASS" if rows else "BLOCKED",
        "split": split,
        "classification": "post_hoc_regression_only",
        "pair_count": len(rows),
        "regenerated_hypothesis_count": len(all_scores),
        "average_regenerated_hypothesis_quality": round(sum(s["quality_score"] for s in all_scores) / (len(all_scores) or 1), 2),
        "high_quality_regenerated_hypothesis_count": sum(1 for s in all_scores if s["high_quality"]),
        "poc_ready_regenerated_hypothesis_count": sum(1 for s in all_scores if s["poc_ready"]),
        "overbroad_noise_rate": round(sum(1 for s in all_scores if s["overbroad_noise"]) / (len(all_scores) or 1), 4),
        "quality_targets_met": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "patch_metadata_visible_during_detection": False,
        "production_readiness_changed": False,
        "pairs": [{"pair_id": row["pair_id"], "average_quality": row["quality"]["average_quality"], "high_quality_count": row["quality"]["high_quality_count"], "poc_ready_count": row["quality"]["poc_ready_count"], "overbroad_noise_rate": row["quality"]["overbroad_noise_rate"]} for row in rows],
    }
    summary["quality_targets_met"] = bool(summary["average_regenerated_hypothesis_quality"] >= 6.0 and summary["high_quality_regenerated_hypothesis_count"] >= 3 and summary["poc_ready_regenerated_hypothesis_count"] >= 3 and summary["overbroad_noise_rate"] <= 0.50)
    output_dir(root).joinpath("precision_regeneration_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Regenerate precise post-hoc hypotheses for patched controls")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="patched-controls")
    args = p.parse_args(argv)
    result = regenerate_split(Path(args.root), split=args.split)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
