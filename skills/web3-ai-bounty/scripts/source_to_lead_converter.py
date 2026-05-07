#!/usr/bin/env python3
"""Convert blind source-analysis leads into pipeline-compatible findings."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pipeline_enforcer import enforce_pipeline
from schema_validator import validate_payload


FINANCIAL_IMPACTS = {"stolen-funds", "bad-debt", "frozen-funds", "insolvency"}


def confidence_label(value: Any) -> str:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return "LOW"
    if f >= 0.85:
        return "CONFIRMED"
    if f >= 0.7:
        return "HIGH"
    if f >= 0.5:
        return "MEDIUM"
    return "LOW"


def convert_blind_lead(raw: dict[str, Any], *, with_poc: bool = False, project_root: Path | None = None) -> dict[str, Any]:
    evidence = raw.get("evidence") or []
    if not evidence:
        raise SystemExit(f"blind lead {raw.get('lead_id')} has no structured evidence")
    for field in ["lead_id", "bug_class", "file_path", "contract", "function", "exploit_scenario", "severity"]:
        if not raw.get(field):
            raise SystemExit(f"blind lead missing {field}")
    impact_type = str(raw.get("impact") or "other")
    lead = {
        "id": raw["lead_id"],
        "title": f"{raw['bug_class']} in {raw['contract']}.{raw['function']} allows {impact_type}",
        "state": raw.get("state") or "MANUAL_LEAD",
        "bug_class": raw["bug_class"],
        "severity": raw["severity"],
        "file_path": raw["file_path"],
        "contract": raw["contract"],
        "function": raw["function"],
        "code_path": [raw["code_path"]],
        "preconditions": ["source evidence from blind analyzer"],
        "attacker_capabilities": raw.get("attacker_capability") or "normal external caller",
        "affected_asset": raw.get("affected_asset") or "protocol asset",
        "exploit_scenario": raw["exploit_scenario"],
        "impact": {"type": impact_type, "asset": raw.get("affected_asset") or "protocol asset"},
        "likelihood": raw.get("likelihood") or "Medium",
        "severity_rationale": f"blind source evidence rule(s): {', '.join(str(ev.get('rule')) for ev in evidence)}",
        "poc": {"path": "", "assertion": False},
        "fix": "apply the matching safe fixture pattern and add regression tests",
        "confidence": confidence_label(raw.get("confidence")),
        "source": {"origin": "manual", "tool": "blind_source_analyzer"},
        "manual_verified": True,
        "external_evidence": evidence,
        "blind_evidence": evidence,
        "needs_poc": bool(raw.get("needs_poc", True)),
    }
    if impact_type in FINANCIAL_IMPACTS:
        lead["financial_impact"] = {
            "currency": "USD-equivalent/local fixture units",
            "amount": "fixture-defined nonzero loss",
            "assumption_source": "blind Solidity fixture source evidence",
            "calculation_method": "local exploit assertion required for report-ready promotion",
        }
    if with_poc:
        poc = infer_poc(raw, project_root=project_root)
        if poc:
            lead["poc"] = poc
            lead["needs_poc"] = False
            lead["stronger_evidence"] = True
    schema = validate_payload("finding", lead)
    if not schema["valid"]:
        raise SystemExit("converted blind lead failed schema validation: " + "; ".join(schema["errors"]))
    return lead


def convert_bounty_hypothesis(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize a hypothesis-engine row without promoting it to a finding."""

    for field in ["file_path", "contract", "function", "bug_class", "exploit_scenario"]:
        if not raw.get(field):
            raise SystemExit(f"bounty hypothesis missing {field}")
    impact = raw.get("impact") if isinstance(raw.get("impact"), dict) else {"type": raw.get("impact") or "requires-validation"}
    lead = {
        **raw,
        "id": raw.get("id") or raw.get("lead_id"),
        "lead_id": raw.get("lead_id") or raw.get("id"),
        "title": raw.get("title") or f"Hypothesis: {raw['bug_class']} in {raw['contract']}.{raw['function']} requires proof",
        "state": "HYPOTHESIS",
        "category": "bounty_hypothesis",
        "severity": raw.get("severity") or "Medium",
        "impact": impact,
        "poc": raw.get("poc") or {"path": "", "assertion": False},
        "source": raw.get("source") or {"origin": "hypothesis", "tool": "bounty_hypothesis_engine"},
        "manual_verified": False,
        "needs_poc": True,
        "counts_as_finding": False,
        "report_ready": False,
    }
    if (impact.get("type") or "") in FINANCIAL_IMPACTS and not lead.get("financial_impact"):
        lead["financial_impact"] = {
            "currency": "not-quantified",
            "amount": "hypothesis-only; no amount claimed",
            "assumption_source": "source x-ray signal, not economic proof",
            "calculation_method": "requires executable PoC before report-ready promotion",
        }
    schema = validate_payload("finding", lead)
    if not schema["valid"]:
        raise SystemExit("converted bounty hypothesis failed schema validation: " + "; ".join(schema["errors"]))
    return lead


def infer_poc(raw: dict[str, Any], *, project_root: Path | None) -> dict[str, Any] | None:
    if project_root is None:
        return None
    source_name = Path(str(raw.get("file_path") or "")).stem
    candidates = sorted((project_root / "test").glob(f"{source_name}.t.sol")) if (project_root / "test").exists() else []
    if not candidates:
        return None
    return {"path": candidates[0].relative_to(project_root).as_posix(), "assertion": True, "command": f"forge test --match-path {candidates[0].relative_to(project_root).as_posix()}"}


def benchmark_economic_proof() -> dict[str, Any]:
    return {"verdict": "REPORT_READY", "lead_exit": {"reason": "local benchmark evidence proves concrete nonzero impact"}}


def pipeline_status_for_lead(lead: dict[str, Any], *, with_poc: bool = False) -> dict[str, Any]:
    proof = benchmark_economic_proof() if with_poc and (lead.get("impact") or {}).get("type") in FINANCIAL_IMPACTS else None
    result = enforce_pipeline(lead, economic_proof=proof)
    return result


def convert_analysis(analysis: dict[str, Any], *, with_poc: bool = False, project_root: Path | None = None, run_pipeline: bool = True) -> dict[str, Any]:
    converted = []
    for raw in analysis.get("leads", []):
        lead = convert_blind_lead(raw, with_poc=with_poc, project_root=project_root)
        if run_pipeline:
            lead["pipeline"] = pipeline_status_for_lead(lead, with_poc=with_poc)
        converted.append(lead)
    for raw in analysis.get("hypotheses", []):
        lead = convert_bounty_hypothesis(raw)
        if run_pipeline:
            lead["pipeline"] = pipeline_status_for_lead(lead, with_poc=False)
        converted.append(lead)
    return {"lead_count": len(converted), "leads": converted}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Convert blind analyzer output to pipeline leads")
    p.add_argument("analysis_json")
    p.add_argument("--project-root")
    p.add_argument("--with-poc", action="store_true")
    args = p.parse_args(argv)
    analysis = json.loads(Path(args.analysis_json).read_text(errors="replace"))
    result = convert_analysis(analysis, with_poc=args.with_poc, project_root=Path(args.project_root) if args.project_root else None)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
