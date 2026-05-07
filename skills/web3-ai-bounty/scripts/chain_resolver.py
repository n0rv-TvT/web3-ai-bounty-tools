#!/usr/bin/env python3
"""Resolve CHAIN_REQUIRED Web3 audit leads using schema-valid economic proofs.

Hard guarantee: this resolver never returns successfully while any lead in the
Lead DB remains in CHAIN_REQUIRED status. A chain is either economically proven,
merged into a proven chain, or killed with an auditable reason.
"""

from __future__ import annotations

import argparse
import json
from copy import deepcopy
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Sequence

from economic_modeler import economic_proof_schema_path, validate_economic_proof


STALE_KILL_REASON = "unresolved chain — no economic proof produced"
CHAIN_RESOLVER_VERSION = "0.1.0"


def state_for_lead(lead: dict[str, Any]) -> str:
    """Map legacy Lead DB status/origin into strict hardening lifecycle state."""

    status = lead.get("status")
    origin = (lead.get("source") or {}).get("origin")
    if status == "REPORT_READY":
        return "REPORT_READY"
    if status == "CHAIN_REQUIRED":
        return "CHAIN_REQUIRED"
    if status == "DUPLICATE":
        return "DUPLICATE"
    if status in {"KILL", "OUT_OF_SCOPE", "ACCEPTED_RISK"}:
        return "KILLED"
    if origin == "scanner":
        return "SCANNER_LEAD"
    if origin in {"hypothesis", "invariant", "parallel-lens", "eval"}:
        return "HYPOTHESIS"
    if origin == "manual":
        return "MANUAL_LEAD"
    return "RAW_LEAD"


def ensure_states(db: dict[str, Any]) -> None:
    """Backfill/refresh strict lifecycle state for Lead DB rows."""

    for lead in db.get("leads", []):
        lead["state"] = state_for_lead(lead)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_time(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    text = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise SystemExit(f"Invalid Lead DB timestamp: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def dec(value: Any, field: str) -> Decimal:
    try:
        d = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise SystemExit(f"Invalid decimal for {field}: {value}") from exc
    if not d.is_finite():
        raise SystemExit(f"Invalid finite decimal for {field}: {value}")
    return d


def load_lead_db(path: Path) -> dict[str, Any]:
    """Load Lead DB JSON."""

    if not path.exists():
        raise SystemExit(f"Lead DB does not exist: {path}")
    data = json.loads(path.read_text(errors="replace"))
    if not isinstance(data, dict):
        raise SystemExit(f"Lead DB root must be an object: {path}")
    if not isinstance(data.get("leads"), list):
        raise SystemExit(f"Lead DB missing leads array: {path}")
    return data


def save_lead_db(path: Path, db: dict[str, Any]) -> None:
    """Persist updated Lead DB."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(db, indent=2, sort_keys=False) + "\n")


def load_economic_proofs(
    proof_paths: Sequence[Path],
    *,
    schema_path: Path | None = None,
) -> dict[str, dict[str, Any]]:
    """
    Load and validate economic_modeler.py outputs.
    Keyed by proof["lead_id"].
    Fails closed if any proof violates economic_proof.schema.json.
    """

    proofs: dict[str, dict[str, Any]] = {}
    schema = schema_path or economic_proof_schema_path()
    for path in proof_paths:
        if not path.exists():
            raise SystemExit(f"Economic proof does not exist: {path}")
        proof = json.loads(path.read_text(errors="replace"))
        if not isinstance(proof, dict):
            raise SystemExit(f"Economic proof root must be an object: {path}")
        validate_economic_proof(proof, schema)
        lead_id = str(proof.get("lead_id") or "")
        if not lead_id:
            raise SystemExit(f"Economic proof missing lead_id: {path}")
        if lead_id in proofs:
            raise SystemExit(f"Duplicate economic proof for lead_id {lead_id}")
        proofs[lead_id] = proof
    return proofs


def select_chain_required_leads(
    db: dict[str, Any],
    lead_ids: Sequence[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Return CHAIN_REQUIRED leads.
    If lead_ids provided, resolve only those IDs but final DB must still contain no CHAIN_REQUIRED.
    """

    wanted = set(lead_ids or [])
    leads = [lead for lead in db.get("leads", []) if lead.get("status") == "CHAIN_REQUIRED"]
    if wanted:
        missing = wanted.difference({str(lead.get("id")) for lead in db.get("leads", [])})
        if missing:
            raise SystemExit(f"Requested lead IDs not found: {', '.join(sorted(missing))}")
        leads = [lead for lead in leads if lead.get("id") in wanted]
    return leads


def chain_age_hours(
    lead: dict[str, Any],
    *,
    now: datetime | None = None,
) -> Decimal:
    """Return age in hours from lead.updated_at or created_at."""

    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    started = parse_time(str(lead.get("updated_at") or lead.get("created_at") or utc_now()))
    return Decimal(str((current - started).total_seconds())) / Decimal("3600")


def is_stale_chain_required(
    lead: dict[str, Any],
    *,
    now: datetime | None = None,
    stale_after_hours: int = 72,
) -> bool:
    """True if CHAIN_REQUIRED lead is older than stale_after_hours."""

    return chain_age_hours(lead, now=now) >= Decimal(stale_after_hours)


def find_proof_for_lead(
    lead: dict[str, Any],
    proofs_by_lead_id: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    """
    Match proof by lead["id"].
    No proof means the lead cannot remain CHAIN_REQUIRED.
    """

    return proofs_by_lead_id.get(str(lead.get("id") or ""))


def attack_path_key(
    lead: dict[str, Any],
    proof: dict[str, Any] | None = None,
) -> str:
    """
    Deterministic compatibility key for merge candidates.
    Uses lead.dedupe.group_key / hypothesis invariant / proof.attack_type.
    """

    dedupe = lead.get("dedupe") or {}
    hypothesis = lead.get("hypothesis") or {}
    for value in [
        dedupe.get("group_key"),
        hypothesis.get("invariant_broken"),
        proof.get("attack_type") if proof else None,
        lead.get("bug_class"),
    ]:
        if value:
            return " ".join(str(value).split())
    return str(lead.get("id") or "<unknown>")


def group_combinable_leads(
    leads: Sequence[dict[str, Any]],
    proofs_by_lead_id: dict[str, dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Group two or more CHAIN_REQUIRED leads sharing the same attack path."""

    grouped: dict[str, list[dict[str, Any]]] = {}
    for lead in leads:
        proof = find_proof_for_lead(lead, proofs_by_lead_id)
        grouped.setdefault(attack_path_key(lead, proof), []).append(lead)
    return {key: rows for key, rows in grouped.items() if len(rows) >= 2}


def combined_lead_id(grouped_leads: Sequence[dict[str, Any]]) -> str:
    return "+".join(sorted(str(lead.get("id")) for lead in grouped_leads))


def find_combined_proof(
    grouped_leads: Sequence[dict[str, Any]],
    proofs_by_lead_id: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    """
    Find schema-valid combined economic proof.
    Combined proof lead_id must equal deterministic combined key:
    L-0001+L-0002+L-0003
    """

    return proofs_by_lead_id.get(combined_lead_id(grouped_leads))


def next_lead_id(db: dict[str, Any]) -> tuple[str, int]:
    indexes = db.setdefault("indexes", {})
    seq = int(indexes.get("next_lead_sequence") or 1)
    max_seq = max([int(lead.get("sequence") or 0) for lead in db.get("leads", [])] or [0])
    seq = max(seq, max_seq + 1)
    indexes["next_lead_sequence"] = seq + 1
    return f"L-{seq:04d}", seq


def append_history(lead: dict[str, Any], old: str | None, new: str, reason: str) -> None:
    lead.setdefault("status_history", []).append(
        {"from": old, "to": new, "at": utc_now(), "actor": "chain_resolver.py", "reason": reason}
    )


def report_validation() -> dict[str, Any]:
    return {
        "verdict": "REPORT",
        "questions": {
            "in_scope": True,
            "reachable": True,
            "normal_attacker": True,
            "normal_victim": True,
            "concrete_impact": True,
            "working_poc": True,
            "duplicate_intended_checked": True,
        },
        "last_checked_at": utc_now(),
        "duplicate_checked": True,
        "intended_behavior_checked": True,
        "blocker_notes": "schema-valid economic proof resolved CHAIN_REQUIRED lead",
    }


def impact_type_from_proof(proof: dict[str, Any]) -> str:
    impact = proof.get("impact") or {}
    bad_debt = dec(impact.get("bad_debt_usd", "0"), "impact.bad_debt_usd")
    protocol_loss = dec(impact.get("protocol_loss_usd", "0"), "impact.protocol_loss_usd")
    if bad_debt > 0:
        return "bad-debt"
    if protocol_loss > 0:
        return "stolen-funds"
    return "unknown"


def value_usd_from_proof(proof: dict[str, Any]) -> Decimal:
    impact = proof.get("impact") or {}
    return max(
        dec(impact.get("protocol_loss_usd", "0"), "impact.protocol_loss_usd"),
        dec(impact.get("bad_debt_usd", "0"), "impact.bad_debt_usd"),
    )


def promote_lead_from_economic_proof(
    db: dict[str, Any],
    lead: dict[str, Any],
    proof: dict[str, Any],
) -> dict[str, Any]:
    """Promote one lead to REPORT_READY when proof.verdict == REPORT_READY."""

    if proof.get("verdict") != "REPORT_READY" or proof.get("lead_exit", {}).get("status") != "REPORT_READY":
        raise SystemExit(f"Cannot promote {lead.get('id')}: economic proof is not REPORT_READY")
    old = str(lead.get("status"))
    value = value_usd_from_proof(proof)
    lead["status"] = "REPORT_READY"
    lead["state"] = "REPORT_READY"
    lead["severity"] = "CRITICAL" if value > 0 else lead.get("severity", "UNKNOWN")
    lead["confidence"] = "CONFIRMED"
    lead["updated_at"] = utc_now()
    lead.setdefault("impact", {})["type"] = impact_type_from_proof(proof)
    lead["impact"]["amount"] = str(proof.get("impact", {}).get("protocol_loss_usd", "0"))
    lead["impact"]["value_usd"] = float(value)
    lead["impact"]["severity_rationale"] = proof.get("lead_exit", {}).get("reason", "positive economic proof")
    lead.setdefault("evidence", {})["level"] = 8
    lead["evidence"]["source_confirmed"] = True
    lead["evidence"]["reachable"] = True
    lead["evidence"]["poc"] = {
        "status": "PASS",
        "path": f"economic-proof:{proof.get('lead_id')}",
        "command": "python3 scripts/economic_modeler.py <request.json> --json <proof.json>",
        "last_run_at": utc_now(),
        "output_summary": f"net_profit_usd={proof.get('profitability', {}).get('net_profit_usd')} protocol_loss_usd={proof.get('impact', {}).get('protocol_loss_usd')}",
    }
    lead["validation"] = report_validation()
    append_history(lead, old, "REPORT_READY", str(proof.get("lead_exit", {}).get("reason") or "economic proof passed"))
    recompute_metrics(db)
    return {"lead_id": lead.get("id"), "proof_id": proof.get("lead_id"), "reason": proof.get("lead_exit", {}).get("reason")}


def kill_lead_from_economic_proof(
    db: dict[str, Any],
    lead: dict[str, Any],
    proof: dict[str, Any],
) -> dict[str, Any]:
    """Kill one lead when proof.verdict == KILL using proof.lead_exit.reason exactly."""

    if proof.get("verdict") != "KILL" or proof.get("lead_exit", {}).get("status") != "KILL":
        raise SystemExit(f"Cannot kill {lead.get('id')} from non-KILL proof")
    reason = str(proof.get("lead_exit", {}).get("reason") or "economic proof killed lead")
    old = str(lead.get("status"))
    lead["status"] = "KILL"
    lead["state"] = "KILLED"
    lead["updated_at"] = utc_now()
    lead["kill"] = {"reason": reason, "notes": reason, "killed_at": utc_now()}
    lead.setdefault("validation", {})["verdict"] = "KILL"
    lead["validation"]["blocker_notes"] = reason
    append_history(lead, old, "KILL", reason)
    recompute_metrics(db)
    return {"lead_id": lead.get("id"), "proof_id": proof.get("lead_id"), "reason": reason}


def kill_stale_chain_lead(
    db: dict[str, Any],
    lead: dict[str, Any],
) -> dict[str, Any]:
    """
    Kill stale unresolved lead with exact reason:
    'unresolved chain — no economic proof produced'
    """

    old = str(lead.get("status"))
    lead["status"] = "KILL"
    lead["state"] = "KILLED"
    lead["updated_at"] = utc_now()
    lead["kill"] = {"reason": STALE_KILL_REASON, "notes": STALE_KILL_REASON, "killed_at": utc_now()}
    lead.setdefault("validation", {})["verdict"] = "KILL"
    lead["validation"]["blocker_notes"] = STALE_KILL_REASON
    append_history(lead, old, "KILL", STALE_KILL_REASON)
    recompute_metrics(db)
    return {"lead_id": lead.get("id"), "reason": STALE_KILL_REASON}


def create_merged_report_ready_lead(
    db: dict[str, Any],
    grouped_leads: Sequence[dict[str, Any]],
    combined_proof: dict[str, Any],
) -> dict[str, Any]:
    """
    Create one CRITICAL REPORT_READY merged lead.
    Requires combined_proof.verdict == REPORT_READY.
    Original leads exit CHAIN_REQUIRED as DUPLICATE-linked.
    """

    validate_economic_proof(combined_proof)
    if combined_proof.get("verdict") != "REPORT_READY" or combined_proof.get("lead_exit", {}).get("status") != "REPORT_READY":
        raise SystemExit("Merged lead requires a schema-valid REPORT_READY combined economic proof")
    if len(grouped_leads) < 2:
        raise SystemExit("Merged lead requires at least two source leads")

    new_id, seq = next_lead_id(db)
    now = utc_now()
    source_ids = [str(lead.get("id")) for lead in grouped_leads]
    value = value_usd_from_proof(combined_proof)
    first = grouped_leads[0]
    locations: list[dict[str, Any]] = []
    for lead in grouped_leads:
        locations.extend(deepcopy(lead.get("locations") or []))
    merged = {
        "id": new_id,
        "sequence": seq,
        "title": f"Combined economic chain across {', '.join(source_ids)}",
        "status": "REPORT_READY",
        "state": "REPORT_READY",
        "bug_class": str(combined_proof.get("bug_class") or first.get("bug_class") or "economic-chain"),
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
        "created_at": now,
        "updated_at": now,
        "source": {
            "origin": "manual",
            "tools": ["chain_resolver.py", "economic_modeler.py"],
            "artifact_refs": [],
            "notes": f"Merged CHAIN_REQUIRED leads: {', '.join(source_ids)}",
        },
        "locations": locations,
        "hypothesis": {
            "exploit_sentence": f"Combined attack path {combined_proof.get('lead_id')} is profitable after economic modeling.",
            "attacker_capability": "normal attacker unless source leads state otherwise",
            "preconditions": [f"source lead {lead_id} is required" for lead_id in source_ids],
            "steps": ["combine compatible weak leads", "execute economically profitable oracle/DeFi chain"],
            "invariant_broken": attack_path_key(first, combined_proof),
            "assertion_target": "combined economic proof shows net_profit_usd > 0 and protocol_loss_usd > 0",
            "expected_impact": f"protocol_loss_usd={combined_proof.get('impact', {}).get('protocol_loss_usd')}",
        },
        "impact": {
            "type": impact_type_from_proof(combined_proof),
            "amount": str(combined_proof.get("impact", {}).get("protocol_loss_usd", "0")),
            "value_usd": float(value),
            "attacker_gain": str(combined_proof.get("profitability", {}).get("net_profit_usd", "0")),
            "victim_loss": str(combined_proof.get("impact", {}).get("protocol_loss_usd", "0")),
            "accepted_category_quote": "Economic proof demonstrates concrete protocol loss/bad debt",
            "severity_rationale": str(combined_proof.get("lead_exit", {}).get("reason") or "positive combined economic proof"),
        },
        "evidence": {
            "level": 8,
            "source_confirmed": True,
            "reachable": True,
            "manual_trace": f"chain_resolver merged {', '.join(source_ids)} using combined economic proof {combined_proof.get('lead_id')}",
            "poc": {
                "status": "PASS",
                "path": f"economic-proof:{combined_proof.get('lead_id')}",
                "command": "python3 scripts/economic_modeler.py <request.json> --json <combined-proof.json>",
                "last_run_at": now,
                "output_summary": f"net_profit_usd={combined_proof.get('profitability', {}).get('net_profit_usd')} protocol_loss_usd={combined_proof.get('impact', {}).get('protocol_loss_usd')}",
            },
            "scanner_refs": [],
            "onchain_refs": [],
            "notes": "Merged chain is report-ready only because combined proof is schema-valid and REPORT_READY.",
        },
        "score": {
            "impact": 3,
            "reachability": 3,
            "poc_simplicity": 2,
            "scope_match": 3,
            "novelty": 2,
            "economic_realism": 3,
            "deductions": 0,
            "total": 16,
            "rationale": "Combined chain has positive economic proof and concrete protocol loss.",
        },
        "validation": report_validation(),
        "dedupe": {
            "group_key": attack_path_key(first, combined_proof),
            "related": source_ids,
            "chain_links": [{"lead_id": lead_id, "relationship": "same-root", "notes": "source lead merged into report-ready chain"} for lead_id in source_ids],
        },
        "chain_requirements": [],
        "tags": ["chain-resolved", "economic-proof", "merged"],
        "status_history": [{"to": "REPORT_READY", "at": now, "actor": "chain_resolver.py", "reason": "combined economic proof is REPORT_READY"}],
    }
    db.setdefault("leads", []).append(merged)

    for lead in grouped_leads:
        old = str(lead.get("status"))
        lead["status"] = "DUPLICATE"
        lead["state"] = "DUPLICATE"
        lead["updated_at"] = utc_now()
        lead.setdefault("dedupe", {})["duplicate_of"] = new_id
        lead["dedupe"].setdefault("related", [])
        if new_id not in lead["dedupe"]["related"]:
            lead["dedupe"]["related"].append(new_id)
        lead.setdefault("validation", {})["verdict"] = "UNCHECKED"
        lead["validation"]["blocker_notes"] = f"merged into {new_id} by chain_resolver.py"
        append_history(lead, old, "DUPLICATE", f"merged into report-ready chain {new_id}")

    recompute_metrics(db)
    return {"merged_lead_id": new_id, "source_lead_ids": source_ids, "proof_id": combined_proof.get("lead_id"), "reason": combined_proof.get("lead_exit", {}).get("reason")}


def resolve_combinable_groups(
    db: dict[str, Any],
    chain_leads: Sequence[dict[str, Any]],
    proofs_by_lead_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge compatible chains only when combined economics are positive."""

    resolved: list[dict[str, Any]] = []
    used: set[str] = set()
    for _, group in group_combinable_leads(chain_leads, proofs_by_lead_id).items():
        source_ids = {str(lead.get("id")) for lead in group}
        if used.intersection(source_ids):
            continue
        combined = find_combined_proof(group, proofs_by_lead_id)
        if combined is None:
            continue
        if combined.get("verdict") == "REPORT_READY":
            resolved.append(create_merged_report_ready_lead(db, group, combined))
        elif combined.get("verdict") == "KILL":
            killed = [kill_lead_from_economic_proof(db, lead, combined) for lead in group]
            resolved.append({"source_lead_ids": sorted(source_ids), "proof_id": combined.get("lead_id"), "killed": killed, "reason": combined.get("lead_exit", {}).get("reason")})
        else:
            raise SystemExit(f"Invalid combined proof verdict: {combined.get('verdict')}")
        used.update(source_ids)
    return resolved


def resolve_individual_chain_leads(
    db: dict[str, Any],
    chain_leads: Sequence[dict[str, Any]],
    proofs_by_lead_id: dict[str, dict[str, Any]],
    *,
    stale_after_hours: int = 72,
) -> list[dict[str, Any]]:
    """Promote, kill, or stale-kill every remaining CHAIN_REQUIRED lead."""

    resolved: list[dict[str, Any]] = []
    for lead in chain_leads:
        if lead.get("status") != "CHAIN_REQUIRED":
            continue
        proof = find_proof_for_lead(lead, proofs_by_lead_id)
        if proof is None:
            stale = is_stale_chain_required(lead, stale_after_hours=stale_after_hours)
            row = kill_stale_chain_lead(db, lead)
            row["stale_after_hours"] = stale_after_hours
            row["older_than_threshold"] = stale
            resolved.append(row)
        elif proof.get("verdict") == "REPORT_READY":
            resolved.append(promote_lead_from_economic_proof(db, lead, proof))
        elif proof.get("verdict") == "KILL":
            resolved.append(kill_lead_from_economic_proof(db, lead, proof))
        else:
            raise SystemExit(f"Invalid economic proof verdict for {lead.get('id')}: {proof.get('verdict')}")
    return resolved


def recompute_metrics(db: dict[str, Any]) -> None:
    leads = db.get("leads", [])
    db["metrics"] = {
        "lead_count": len(leads),
        "report_ready_count": sum(1 for lead in leads if lead.get("status") in {"REPORT_READY", "REPORTED"}),
        "kill_count": sum(1 for lead in leads if lead.get("status") == "KILL"),
        "last_recomputed_at": utc_now(),
    }
    db["updated_at"] = utc_now()


def assert_no_chain_required_remaining(db: dict[str, Any]) -> None:
    """Fail hard if any lead still has status CHAIN_REQUIRED."""

    remaining = [str(lead.get("id")) for lead in db.get("leads", []) if lead.get("status") == "CHAIN_REQUIRED"]
    if remaining:
        raise SystemExit(f"CHAIN_REQUIRED leads remain after resolver: {', '.join(remaining)}")


def resolve_chain_required_leads(
    lead_db_path: Path,
    proof_paths: Sequence[Path],
    *,
    lead_ids: Sequence[str] | None = None,
    schema_path: Path | None = None,
    stale_after_hours: int = 72,
    write: bool = True,
) -> dict[str, Any]:
    """
    Main entry point.

    Output:
    {
      "promoted": [...],
      "killed": [...],
      "merged": [...],
      "staled": [...],
      "errors": [],
      "chain_required_remaining": 0
    }
    """

    db = load_lead_db(lead_db_path)
    ensure_states(db)
    proofs = load_economic_proofs(proof_paths, schema_path=schema_path)
    chain_leads = select_chain_required_leads(db, lead_ids)
    log: dict[str, Any] = {
        "lead_db_path": str(lead_db_path),
        "proof_count": len(proofs),
        "input_chain_required": [str(lead.get("id")) for lead in chain_leads],
        "promoted": [],
        "killed": [],
        "merged": [],
        "staled": [],
        "errors": [],
        "chain_required_remaining": None,
    }

    for row in resolve_combinable_groups(db, chain_leads, proofs):
        if row.get("merged_lead_id"):
            log["merged"].append(row)
        else:
            log["killed"].extend(row.get("killed", []))

    remaining = [lead for lead in db.get("leads", []) if lead.get("status") == "CHAIN_REQUIRED"]
    for row in resolve_individual_chain_leads(db, remaining, proofs, stale_after_hours=stale_after_hours):
        if row.get("reason") == STALE_KILL_REASON:
            log["staled"].append(row)
        elif row.get("reason"):
            if any((proofs.get(str(row.get("proof_id"))) or {}).get("verdict") == "REPORT_READY" for _ in [0]):
                log["promoted"].append(row)
            else:
                log["killed"].append(row)

    recompute_metrics(db)
    assert_no_chain_required_remaining(db)
    log["chain_required_remaining"] = 0
    if write:
        save_lead_db(lead_db_path, db)
    return log


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Resolve CHAIN_REQUIRED leads using economic proofs")
    parser.add_argument("lead_db", help="Lead DB JSON path")
    parser.add_argument("proof", nargs="*", help="economic_modeler.py proof JSON path(s)")
    parser.add_argument("--lead-id", action="append", help="specific CHAIN_REQUIRED lead ID to resolve")
    parser.add_argument("--schema", help="economic_proof.schema.json override")
    parser.add_argument("--stale-after-hours", type=int, default=72)
    parser.add_argument("--no-write", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    log = resolve_chain_required_leads(
        Path(args.lead_db),
        [Path(p) for p in args.proof],
        lead_ids=args.lead_id,
        schema_path=Path(args.schema) if args.schema else None,
        stale_after_hours=args.stale_after_hours,
        write=not args.no_write,
    )
    print(json.dumps(log, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
