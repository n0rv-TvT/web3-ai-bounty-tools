#!/usr/bin/env python3
"""Read-only output-layer triage gate for Web3 audit leads.

The enforcer never mutates Lead DB state. It decides whether a lead may proceed
to report generation. Status transitions remain owned by lead_db.py and
chain_resolver.py.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Sequence

from chain_resolver import STALE_KILL_REASON, is_stale_chain_required
from economic_modeler import economic_proof_schema_path, validate_economic_proof


VALIDATION_GATE_ORDER = [
    "in_scope",
    "reachable",
    "normal_attacker",
    "normal_victim",
    "concrete_impact",
    "working_poc",
    "duplicate_intended_checked",
]


def dec(value: Any, field: str) -> Decimal:
    try:
        d = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise SystemExit(f"Invalid decimal for {field}: {value}") from exc
    if not d.is_finite():
        raise SystemExit(f"Invalid finite decimal for {field}: {value}")
    return d


def load_lead_db(path: Path) -> dict[str, Any]:
    """Load Lead DB JSON without mutating it."""

    if not path.exists():
        raise SystemExit(f"Lead DB does not exist: {path}")
    data = json.loads(path.read_text(errors="replace"))
    if not isinstance(data, dict):
        raise SystemExit(f"Lead DB root must be an object: {path}")
    if not isinstance(data.get("leads"), list):
        raise SystemExit(f"Lead DB missing leads array: {path}")
    return data


def load_resolution_log(path: Path | None) -> dict[str, Any] | None:
    """Load chain_resolver.py resolution log if provided."""

    if path is None:
        return None
    if not path.exists():
        raise SystemExit(f"Resolution log does not exist: {path}")
    data = json.loads(path.read_text(errors="replace"))
    if not isinstance(data, dict):
        raise SystemExit(f"Resolution log root must be an object: {path}")
    return data


def load_economic_proofs(
    proof_paths: Sequence[Path],
    *,
    schema_path: Path | None = None,
) -> dict[str, dict[str, Any]]:
    """
    Load and schema-validate economic_modeler.py proofs.
    Keyed by proof["lead_id"].
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


def select_leads_for_triage(
    db: dict[str, Any],
    lead_ids: Sequence[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Select leads to enforce.
    Defaults to REPORT_READY leads, because enforcer guards output-layer access.
    """

    wanted = set(lead_ids or [])
    if wanted:
        leads = [lead for lead in db.get("leads", []) if str(lead.get("id")) in wanted]
        found = {str(lead.get("id")) for lead in leads}
        missing = wanted.difference(found)
        if missing:
            raise SystemExit(f"Requested lead IDs not found: {', '.join(sorted(missing))}")
        return leads
    return [lead for lead in db.get("leads", []) if lead.get("status") == "REPORT_READY"]


def _combined_id_from_related(lead: dict[str, Any]) -> str | None:
    dedupe = lead.get("dedupe") or {}
    related = [str(x) for x in dedupe.get("related") or [] if str(x)]
    if len(related) >= 2:
        return "+".join(sorted(related))
    linked = []
    for link in dedupe.get("chain_links") or []:
        if isinstance(link, dict) and link.get("lead_id"):
            linked.append(str(link["lead_id"]))
    if len(linked) >= 2:
        return "+".join(sorted(linked))
    return None


def _proof_id_from_poc_path(lead: dict[str, Any]) -> str | None:
    poc = ((lead.get("evidence") or {}).get("poc") or {})
    path = str(poc.get("path") or "")
    prefix = "economic-proof:"
    if path.startswith(prefix):
        return path[len(prefix) :]
    return None


def find_economic_proof_for_lead(
    lead: dict[str, Any],
    proofs_by_lead_id: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    """
    Match direct proof by lead["id"] or merged proof by lead.dedupe.related/chain_links.
    """

    candidates = [
        str(lead.get("id") or ""),
        _proof_id_from_poc_path(lead),
        _combined_id_from_related(lead),
    ]
    for candidate in candidates:
        if candidate and candidate in proofs_by_lead_id:
            return proofs_by_lead_id[candidate]
    return None


def economic_impact_positive(proof: dict[str, Any]) -> bool:
    """True if bad_debt_usd > 0 or protocol_loss_usd > 0."""

    impact = proof.get("impact") or {}
    bad_debt = dec(impact.get("bad_debt_usd", "0"), "impact.bad_debt_usd")
    protocol_loss = dec(impact.get("protocol_loss_usd", "0"), "impact.protocol_loss_usd")
    return bad_debt > 0 or protocol_loss > 0


def economic_profit_positive(proof: dict[str, Any]) -> bool:
    """True if profitability.net_profit_usd > 0."""

    return dec((proof.get("profitability") or {}).get("net_profit_usd", "0"), "profitability.net_profit_usd") > 0


def pass_gate(name: str) -> dict[str, Any]:
    return {"gate": name, "decision": "PASS", "reason": "passed"}


def block_gate(name: str, reason: str) -> dict[str, Any]:
    return {"gate": name, "decision": "BLOCK", "reason": reason}


def enforce_economic_gate(
    lead: dict[str, Any],
    proof: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    PASS only if economic proof exists, is REPORT_READY, profitable, and has impact.
    """

    del lead
    if proof is None:
        return block_gate("economic", "missing economic proof")
    if proof.get("verdict") == "KILL" or proof.get("lead_exit", {}).get("status") == "KILL":
        return block_gate("economic", str(proof.get("lead_exit", {}).get("reason") or "economic proof killed lead"))
    if proof.get("verdict") != "REPORT_READY" or proof.get("lead_exit", {}).get("status") != "REPORT_READY":
        return block_gate("economic", "economic proof is not REPORT_READY")
    if not economic_profit_positive(proof):
        return block_gate("economic", "non-positive net profit")
    if not economic_impact_positive(proof):
        return block_gate("economic", "missing concrete economic impact")
    return pass_gate("economic")


def enforce_chain_resolver_gate(
    db: dict[str, Any],
    resolution_log: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    PASS only if chain resolver ran, chain_required_remaining == 0, and DB has no CHAIN_REQUIRED.
    """

    chain_leads = [lead for lead in db.get("leads", []) if lead.get("status") == "CHAIN_REQUIRED"]
    stale = [lead for lead in chain_leads if is_stale_chain_required(lead)]
    if stale:
        return block_gate("chain_resolver", STALE_KILL_REASON)
    if chain_leads:
        return block_gate("chain_resolver", "unresolved chain leads remain")
    if resolution_log is None:
        return block_gate("chain_resolver", "missing chain resolver log")
    if resolution_log.get("chain_required_remaining") != 0:
        return block_gate("chain_resolver", "unresolved chain leads remain")
    return pass_gate("chain_resolver")


def false_validation_gates(lead: dict[str, Any]) -> list[str]:
    """Return names of seven validation questions that are not true."""

    questions = ((lead.get("validation") or {}).get("questions") or {})
    return [gate for gate in VALIDATION_GATE_ORDER if questions.get(gate) is not True]


def enforce_validation_gate(lead: dict[str, Any]) -> dict[str, Any]:
    """
    PASS only if all seven validation gates are true.
    BLOCK reason includes gate name, e.g. validation gate false: working_poc.
    """

    false_gates = false_validation_gates(lead)
    if false_gates:
        return block_gate("validation", f"validation gate false: {false_gates[0]}")
    return pass_gate("validation")


def enforce_poc_gate(lead: dict[str, Any]) -> dict[str, Any]:
    """
    PASS only if lead.evidence.poc.path exists and is non-empty.
    BLOCK reason: missing PoC artifact.
    """

    poc = ((lead.get("evidence") or {}).get("poc") or {})
    if not str(poc.get("path") or "").strip():
        return block_gate("poc", "missing PoC artifact")
    return pass_gate("poc")


def combine_gate_results(
    lead: dict[str, Any],
    gate_results: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    """
    Return final per-lead triage decision:
    - PASS if all gates PASS
    - BLOCK on first failing gate, preserving exact reason
    """

    for result in gate_results:
        if result.get("decision") == "BLOCK":
            return {
                "lead_id": lead.get("id"),
                "decision": "BLOCK",
                "reason": result.get("reason"),
                "failed_gate": result.get("gate"),
                "gates": list(gate_results),
            }
    return {
        "lead_id": lead.get("id"),
        "decision": "PASS",
        "reason": "all triage gates passed",
        "failed_gate": None,
        "gates": list(gate_results),
    }


def enforce_lead_triage(
    lead: dict[str, Any],
    db: dict[str, Any],
    proofs_by_lead_id: dict[str, dict[str, Any]],
    resolution_log: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Enforce all output-layer gates for one lead.
    Does not mutate lead status.
    """

    proof = find_economic_proof_for_lead(lead, proofs_by_lead_id)
    gate_results = [
        enforce_economic_gate(lead, proof),
        enforce_chain_resolver_gate(db, resolution_log),
        enforce_validation_gate(lead),
        enforce_poc_gate(lead),
    ]
    return combine_gate_results(lead, gate_results)


def enforce_triage(
    lead_db_path: Path,
    proof_paths: Sequence[Path],
    *,
    resolution_log_path: Path | None = None,
    lead_ids: Sequence[str] | None = None,
    schema_path: Path | None = None,
) -> dict[str, Any]:
    """
    Main entry point.

    Output:
    {
      "lead_db_path": "...",
      "checked": [...],
      "passed": [...],
      "blocked": [...],
      "summary": {
        "pass_count": 0,
        "block_count": 1
      }
    }
    """

    db = load_lead_db(lead_db_path)
    proofs = load_economic_proofs(proof_paths, schema_path=schema_path)
    resolution_log = load_resolution_log(resolution_log_path)
    leads = select_leads_for_triage(db, lead_ids)
    checked = [enforce_lead_triage(lead, db, proofs, resolution_log) for lead in leads]
    passed = [row for row in checked if row.get("decision") == "PASS"]
    blocked = [row for row in checked if row.get("decision") == "BLOCK"]
    return {
        "lead_db_path": str(lead_db_path),
        "proof_count": len(proofs),
        "resolution_log_present": resolution_log is not None,
        "checked": checked,
        "passed": passed,
        "blocked": blocked,
        "summary": {"pass_count": len(passed), "block_count": len(blocked)},
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only REPORT_READY triage enforcer")
    parser.add_argument("lead_db")
    parser.add_argument("proof", nargs="*", help="economic_modeler.py proof JSON path(s)")
    parser.add_argument("--resolution-log", help="chain_resolver.py output log JSON")
    parser.add_argument("--lead-id", action="append")
    parser.add_argument("--schema", help="economic_proof.schema.json override")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = enforce_triage(
        Path(args.lead_db),
        [Path(p) for p in args.proof],
        resolution_log_path=Path(args.resolution_log) if args.resolution_log else None,
        lead_ids=args.lead_id,
        schema_path=Path(args.schema) if args.schema else None,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
