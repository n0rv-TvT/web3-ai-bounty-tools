#!/usr/bin/env python3
"""Production-oriented JSON lead database CLI for Web3 audits.

Stdlib-first. If `jsonschema` is installed, `validate` also performs full
JSON Schema validation against schemas/lead_database.schema.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from finding_state_machine import can_transition, create_scanner_lead
    from feedback_memory import query_feedback_memory
except Exception:  # pragma: no cover - CLI still works when imported standalone in sparse environments
    can_transition = None  # type: ignore
    create_scanner_lead = None  # type: ignore
    query_feedback_memory = None  # type: ignore


SCHEMA_VERSION = "1.0.0"
STATUSES = {
    "INTAKE", "LEAD", "INVESTIGATING", "PROVE", "POC_READY", "VALIDATION_READY",
    "REPORT_READY", "REPORTED", "CHAIN_REQUIRED", "KILL", "DUPLICATE", "OUT_OF_SCOPE", "ACCEPTED_RISK",
}
SEVERITIES = {"UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
CONFIDENCES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CONFIRMED"}
KILL_REASONS = {
    "out-of-scope", "not-reachable", "no-concrete-impact", "intended-behavior", "duplicate",
    "scanner-only", "admin-only", "excluded", "poc-failed", "dust-only", "self-harm", "other",
}


def state_for_origin(origin: str | None, status: str | None = None) -> str:
    """Map Lead DB origin/status into the strict finding state machine."""

    if status == "REPORT_READY":
        return "REPORT_READY"
    if status == "CHAIN_REQUIRED":
        return "CHAIN_REQUIRED"
    if status in {"KILL", "OUT_OF_SCOPE", "ACCEPTED_RISK"}:
        return "KILLED"
    if status == "DUPLICATE":
        return "DUPLICATE"
    if origin == "scanner":
        return "SCANNER_LEAD"
    if origin in {"hypothesis", "invariant", "parallel-lens", "eval"}:
        return "HYPOTHESIS"
    if origin == "manual":
        return "MANUAL_LEAD"
    return "RAW_LEAD"


def ensure_lead_state(lead: dict[str, Any]) -> str:
    """Ensure every lead has a state field without changing its status."""

    state = lead.get("state") or state_for_origin((lead.get("source") or {}).get("origin"), lead.get("status"))
    lead["state"] = state
    return state


def validate_state_promotion(lead: dict[str, Any], target_state: str, *, economic_proof: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validate a Lead DB lead against finding_state_machine before promotion."""

    if can_transition is None:
        raise SystemExit("finding_state_machine.py is required for Lead DB state promotion")
    candidate = lead_to_finding_gate(lead, economic_proof=economic_proof)
    return can_transition(candidate, target_state)  # type: ignore[misc]


def normalize_economic_proof_for_gate(economic_proof: dict[str, Any] | None) -> dict[str, Any] | None:
    """Convert full economic_modeler output into finding_state_machine proof shape."""

    if not economic_proof:
        return None
    if economic_proof.get("schema_valid") is True:
        return economic_proof
    schema_valid = bool((economic_proof.get("validation") or {}).get("schema_validated")) or economic_proof.get("verdict") == "REPORT_READY"
    return {"schema_valid": schema_valid, "verdict": economic_proof.get("verdict")}


def lead_to_finding_gate(lead: dict[str, Any], *, economic_proof: dict[str, Any] | None = None) -> dict[str, Any]:
    """Convert a Lead DB row into finding_state_machine gate input."""

    ensure_lead_state(lead)
    loc = (lead.get("locations") or [{}])[0]
    impact = lead.get("impact") or {}
    evidence = lead.get("evidence") or {}
    hypothesis = lead.get("hypothesis") or {}
    return {
        "state": lead.get("state"),
        "file_path": loc.get("file"),
        "contract": loc.get("contract"),
        "function": loc.get("function"),
        "code_path": hypothesis.get("steps") or evidence.get("manual_trace"),
        "preconditions": hypothesis.get("preconditions"),
        "attacker_capabilities": hypothesis.get("attacker_capability"),
        "affected_asset": impact.get("asset") or impact.get("type"),
        "exploit_scenario": hypothesis.get("exploit_sentence"),
        "impact": impact,
        "impact_type": impact.get("type"),
        "likelihood": lead.get("confidence"),
        "severity_rationale": impact.get("severity_rationale") or (lead.get("score") or {}).get("rationale"),
        "poc": evidence.get("poc"),
        "fix": lead.get("remediation") or impact.get("remediation") or "specific remediation required",
        "confidence": lead.get("confidence"),
        "duplicate_of": (lead.get("dedupe") or {}).get("duplicate_of"),
        "duplicate_root_cause": bool((lead.get("dedupe") or {}).get("duplicate_of")),
        "economic_proof": normalize_economic_proof_for_gate(economic_proof),
    }


def promote_lead_state(lead: dict[str, Any], target_state: str, *, economic_proof: dict[str, Any] | None = None) -> dict[str, Any]:
    """Promote a lead state only if finding_state_machine permits it."""

    result = validate_state_promotion(lead, target_state, economic_proof=economic_proof)
    if not result.get("allowed"):
        raise SystemExit(json.dumps(result, indent=2))
    lead["state"] = target_state
    if target_state == "REPORT_READY":
        lead["status"] = "REPORT_READY"
    return lead


def apply_feedback_memory_to_lead(lead: dict[str, Any], memory: dict[str, Any], report_text: str) -> dict[str, Any]:
    """Apply explainable feedback-memory adjustment to a lead score/confidence."""

    if query_feedback_memory is None:
        raise SystemExit("feedback_memory.py is required for memory scoring")
    result = query_feedback_memory(memory, future_lead=lead, future_report=report_text)  # type: ignore[misc]
    lead.setdefault("memory", {})["feedback"] = result
    return result


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def short_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def schema_path() -> Path:
    return Path(__file__).resolve().parents[1] / "schemas" / "lead_database.schema.json"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(errors="replace"))


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n")


def git_value(args: list[str], repo: str | None) -> str | None:
    if not repo:
        return None
    try:
        return subprocess.check_output(["git", *args], cwd=repo, text=True, stderr=subprocess.DEVNULL).strip() or None
    except Exception:
        return None


def empty_questions() -> dict[str, bool]:
    return {
        "in_scope": False,
        "reachable": False,
        "normal_attacker": False,
        "normal_victim": False,
        "concrete_impact": False,
        "working_poc": False,
        "duplicate_intended_checked": False,
    }


def recompute_metrics(db: dict[str, Any]) -> None:
    leads = db.get("leads", [])
    db["metrics"] = {
        "lead_count": len(leads),
        "report_ready_count": sum(1 for l in leads if l.get("status") in {"REPORT_READY", "REPORTED"}),
        "kill_count": sum(1 for l in leads if l.get("status") == "KILL"),
        "last_recomputed_at": now(),
    }


def touch(db: dict[str, Any]) -> None:
    db["updated_at"] = now()
    recompute_metrics(db)


def init_db(args: argparse.Namespace) -> int:
    path = Path(args.database)
    if path.exists() and not args.force:
        raise SystemExit(f"Refusing to overwrite existing database: {path} (use --force)")
    repo = args.repo
    ts = now()
    audit = {
        "session_id": short_id("audit"),
        "target_name": args.target,
        "mode": args.mode,
        "protocol_types": args.protocol or [],
        "repo_path": repo or ".",
        "repo_remote": git_value(["remote", "get-url", "origin"], repo),
        "branch": git_value(["rev-parse", "--abbrev-ref", "HEAD"], repo),
        "commit": git_value(["rev-parse", "HEAD"], repo),
        "chain_ids": args.chain_id or [],
        "notes": args.notes or "",
    }
    audit = {k: v for k, v in audit.items() if v is not None}
    db = {
        "schema_version": SCHEMA_VERSION,
        "database_id": short_id("ldb"),
        "created_at": ts,
        "updated_at": ts,
        "audit": audit,
        "scope": {
            "status": "DRAFT",
            "assets": [],
            "impact_categories": [],
            "exclusions": [],
        },
        "artifacts": [],
        "leads": [],
        "indexes": {"next_lead_sequence": 1, "next_artifact_sequence": 1},
        "metrics": {"lead_count": 0, "report_ready_count": 0, "kill_count": 0, "last_recomputed_at": ts},
    }
    save_json(path, db)
    print(f"Initialized lead database: {path}")
    return 0


def make_group_key(contract: str | None, function: str | None, bug_class: str) -> str:
    return f"{contract or '<unknown>'} | {function or '<unknown>'} | {bug_class}"


def default_lead(seq: int, args: argparse.Namespace) -> dict[str, Any]:
    ts = now()
    lead_id = f"L-{seq:04d}"
    location = {k: v for k, v in {
        "file": args.file,
        "contract": args.contract,
        "function": args.function,
        "line_start": args.line,
        "chain_id": args.chain_id,
        "address": args.address,
        "implementation": args.implementation,
    }.items() if v is not None}
    status = args.status or "LEAD"
    bug_class = args.bug_class
    return {
        "id": lead_id,
        "sequence": seq,
        "title": args.title,
        "status": status,
        "state": state_for_origin(args.origin or "manual", status),
        "bug_class": bug_class,
        "severity": args.severity or "UNKNOWN",
        "confidence": args.confidence or "UNKNOWN",
        "created_at": ts,
        "updated_at": ts,
        "source": {
            "origin": args.origin or "manual",
            "tools": [args.tool] if args.tool else [],
            "artifact_refs": [],
            "notes": args.source_notes or "",
        },
        "locations": [location] if location else [],
        "hypothesis": {
            "exploit_sentence": args.exploit_sentence or "",
            "attacker_capability": args.attacker_capability or "",
            "preconditions": args.precondition or [],
            "steps": args.step or [],
            "invariant_broken": args.invariant or "",
            "assertion_target": args.assertion_target or "",
            "expected_impact": args.expected_impact or "",
        },
        "impact": {
            "type": args.impact_type or "unknown",
            "asset": args.asset or "",
            "amount": args.amount or "",
            "accepted_category_quote": args.accepted_category or "",
            "severity_rationale": args.severity_rationale or "",
        },
        "evidence": {
            "level": args.evidence_level if args.evidence_level is not None else 1,
            "source_confirmed": bool(args.source_confirmed),
            "reachable": bool(args.reachable),
            "manual_trace": args.manual_trace or "",
            "poc": {"status": "NONE"},
            "scanner_refs": [],
            "onchain_refs": [],
            "notes": args.evidence_notes or "",
        },
        "score": {
            "impact": args.score_impact,
            "reachability": args.score_reachability,
            "poc_simplicity": args.score_poc,
            "scope_match": args.score_scope,
            "novelty": args.score_novelty,
            "economic_realism": args.score_economics,
            "deductions": args.score_deductions,
            "total": args.score_impact + args.score_reachability + args.score_poc + args.score_scope + args.score_novelty + args.score_economics + args.score_deductions,
            "rationale": args.score_rationale or "",
        },
        "validation": {
            "verdict": "UNCHECKED",
            "questions": empty_questions(),
            "duplicate_checked": False,
            "intended_behavior_checked": False,
            "blocker_notes": "",
        },
        "dedupe": {
            "group_key": args.group_key or make_group_key(args.contract, args.function, bug_class),
            "related": [],
            "chain_links": [],
        },
        "chain_requirements": args.chain_requirement or [],
        "tags": args.tag or [],
        "status_history": [{"to": status, "at": ts, "actor": "lead_db.py", "reason": args.reason or "lead created"}],
    }


def add_lead(args: argparse.Namespace) -> int:
    path = Path(args.database)
    db = load_json(path)
    seq = int(db["indexes"]["next_lead_sequence"])
    lead = default_lead(seq, args)
    db["leads"].append(lead)
    db["indexes"]["next_lead_sequence"] = seq + 1
    touch(db)
    save_json(path, db)
    print(f"Added {lead['id']}: {lead['title']}")
    return 0


def find_lead(db: dict[str, Any], lead_id: str) -> dict[str, Any]:
    for lead in db.get("leads", []):
        if lead.get("id") == lead_id:
            return lead
    raise SystemExit(f"Lead not found: {lead_id}")


def update_status(args: argparse.Namespace) -> int:
    if args.status not in STATUSES:
        raise SystemExit(f"Invalid status: {args.status}")
    db_path = Path(args.database)
    db = load_json(db_path)
    lead = find_lead(db, args.lead_id)
    old = lead.get("status")
    ts = now()
    lead["status"] = args.status
    lead["state"] = state_for_origin((lead.get("source") or {}).get("origin"), args.status)
    lead["updated_at"] = ts
    lead.setdefault("status_history", []).append({"from": old, "to": args.status, "at": ts, "actor": "lead_db.py", "reason": args.reason or "status update"})
    if args.status == "KILL":
        reason = args.kill_reason or "other"
        if reason not in KILL_REASONS:
            raise SystemExit(f"Invalid kill reason: {reason}")
        lead["kill"] = {"reason": reason, "notes": args.reason or "", "killed_at": ts}
        lead["validation"]["verdict"] = "KILL"
    if args.status == "CHAIN_REQUIRED":
        if args.chain_requirement:
            lead["chain_requirements"] = args.chain_requirement
        lead["validation"]["verdict"] = "CHAIN_REQUIRED"
    touch(db)
    save_json(db_path, db)
    print(f"Updated {args.lead_id}: {old} -> {args.status}")
    return 0


def add_poc(args: argparse.Namespace) -> int:
    db_path = Path(args.database)
    db = load_json(db_path)
    lead = find_lead(db, args.lead_id)
    ts = now()
    lead["evidence"]["poc"] = {
        "status": args.status,
        "path": args.path,
        "command": args.command,
        "last_run_at": ts,
        "output_summary": args.summary or "",
    }
    if args.chain_id or args.block_number or args.rpc_env:
        lead["evidence"]["poc"]["fork"] = {
            k: v for k, v in {"chain_id": args.chain_id, "block_number": args.block_number, "rpc_env": args.rpc_env}.items() if v is not None
        }
    lead["updated_at"] = ts
    if args.status == "PASS":
        lead["evidence"]["level"] = max(int(lead["evidence"].get("level", 0)), 6)
        lead["validation"]["questions"]["working_poc"] = True
    elif args.status in {"WRITTEN", "FAIL"}:
        lead["evidence"]["level"] = max(int(lead["evidence"].get("level", 0)), 5)
    touch(db)
    save_json(db_path, db)
    print(f"Updated PoC for {args.lead_id}: {args.status}")
    return 0


def set_gate(args: argparse.Namespace) -> int:
    db_path = Path(args.database)
    db = load_json(db_path)
    lead = find_lead(db, args.lead_id)
    q = lead["validation"]["questions"]
    for key in q:
        value = getattr(args, key.replace("_", "-"), None)
        if value is not None:
            q[key] = value
    # argparse cannot create attrs with dashes; set manually
    mapping = {
        "in_scope": args.in_scope,
        "reachable": args.reachable,
        "normal_attacker": args.normal_attacker,
        "normal_victim": args.normal_victim,
        "concrete_impact": args.concrete_impact,
        "working_poc": args.working_poc,
        "duplicate_intended_checked": args.duplicate_intended_checked,
    }
    for key, val in mapping.items():
        if val is not None:
            q[key] = val
    verdict = "REPORT" if all(q.values()) else (args.verdict or "UNCHECKED")
    lead["validation"].update({
        "verdict": verdict,
        "last_checked_at": now(),
        "duplicate_checked": bool(q["duplicate_intended_checked"]),
        "intended_behavior_checked": bool(q["duplicate_intended_checked"]),
        "blocker_notes": args.notes or lead["validation"].get("blocker_notes", ""),
    })
    # Keep the evidence summary coherent with the explicit validation gate. The
    # gate remains the source of truth for report promotion, but downstream
    # agents and report templates often read evidence.reachable/source_confirmed.
    if q.get("reachable"):
        lead.setdefault("evidence", {})["reachable"] = True
    if q.get("in_scope") and q.get("concrete_impact"):
        lead.setdefault("evidence", {})["source_confirmed"] = True
    if verdict == "REPORT" and args.promote:
        if lead.get("evidence", {}).get("poc", {}).get("status") != "PASS":
            raise SystemExit(f"Refusing to promote {args.lead_id}: evidence.poc.status must be PASS")
        old = lead["status"]
        lead["status"] = "REPORT_READY"
        lead["state"] = "REPORT_READY"
        lead["evidence"]["level"] = max(int(lead["evidence"].get("level", 0)), 8)
        if old != "REPORT_READY":
            lead.setdefault("status_history", []).append({"from": old, "to": "REPORT_READY", "at": now(), "actor": "lead_db.py", "reason": "validation gate passed"})
    touch(db)
    save_json(db_path, db)
    print(f"Validation for {args.lead_id}: {lead['validation']['verdict']}")
    return 0


def import_scanner(args: argparse.Namespace) -> int:
    db_path = Path(args.database)
    db = load_json(db_path)
    payload = load_json(Path(args.normalized_json))
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict) and isinstance(payload.get("leads"), list):
        rows = list(payload.get("leads") or [])
        if args.include_killed and isinstance(payload.get("suppressed"), list):
            # Canonical scanner reports generated with --include-killed already
            # include KILL rows in report.leads and also mirror them in
            # report.suppressed for readability. Avoid importing the same killed
            # scanner row twice when callers request suppressed-row auditability.
            def row_key(row: dict[str, Any]) -> str:
                return str(
                    row.get("fingerprint")
                    or row.get("dedupe_key")
                    or json.dumps(
                        {
                            "tool": row.get("tool"),
                            "rule_id": row.get("rule_id"),
                            "file": row.get("file"),
                            "line": row.get("line"),
                            "status": row.get("status"),
                        },
                        sort_keys=True,
                    )
                )

            seen_rows = {row_key(r) for r in rows if isinstance(r, dict)}
            for suppressed in payload.get("suppressed") or []:
                if not isinstance(suppressed, dict):
                    continue
                key = row_key(suppressed)
                if key in seen_rows:
                    continue
                rows.append(suppressed)
                seen_rows.add(key)
    else:
        raise SystemExit("normalized scanner JSON must be a list or canonical report with a leads array")
    imported = 0
    skipped = 0
    for row in rows:
        row_status = str(row.get("status") or row.get("triage_verdict") or "LEAD").upper().replace(" ", "_")
        if row_status in {"SUPPRESSED", "FALSE_POSITIVE"}:
            row_status = "KILL"
        if row_status == "KILL" and not args.include_killed:
            skipped += 1
            continue
        if row_status not in STATUSES:
            row_status = "LEAD"
        if row_status == "REPORT_READY":
            row_status = "LEAD"
        score = row.get("score") or {}
        tags = list(dict.fromkeys(["scanner", *(row.get("tags") or []), str(row.get("tool") or "scanner"), str(row.get("bug_class") or "scanner-signal")]))
        tools = row.get("tools") or [row.get("tool") or "scanner"]
        if isinstance(tools, str):
            tools = [tools]
        impact_type = row.get("impact_type") or row.get("impact_hint") or "unknown"
        if impact_type not in {"unknown", "stolen-funds", "frozen-funds", "bad-debt", "unauthorized-privileged-action", "account-takeover", "sensitive-data-exposure", "unsafe-signing-tool-execution", "governance-corruption", "other"}:
            impact_type = "unknown"
        proof_questions = row.get("proof_questions") or []
        chain_requirements = row.get("chain_requirements") or []
        if row_status == "CHAIN_REQUIRED" and not chain_requirements:
            chain_requirements = [row.get("proof_needed") or "scanner signal requires an additional impact/reachability chain"]
        seq = int(db["indexes"]["next_lead_sequence"])
        ns = argparse.Namespace(
            title=row.get("title") or f"{row.get('bug_class', 'scanner-lead')} at {row.get('file') or '<unknown>'}:{row.get('line') or '-'}",
            status=row_status,
            bug_class=str(row.get("bug_class") or "scanner-lead"),
            severity=str(row.get("severity") or "UNKNOWN").upper() if str(row.get("severity") or "").upper() in SEVERITIES else "UNKNOWN",
            confidence=str(row.get("confidence") or "UNKNOWN").upper() if str(row.get("confidence") or "").upper() in CONFIDENCES else "UNKNOWN",
            file=row.get("file"), contract=row.get("contract"), function=row.get("function"), line=row.get("line"), chain_id=None, address=None, implementation=None,
            origin="scanner", tool=(tools[0] if tools else row.get("tool")), source_notes=f"{row.get('rule_id') or ''} {row.get('message') or ''}".strip(),
            exploit_sentence=row.get("exploit_hypothesis") or "", attacker_capability="normal attacker unless manual triage proves otherwise", precondition=proof_questions, step=[], invariant="", assertion_target="", expected_impact=row.get("impact_hint") or "",
            impact_type=impact_type, asset="", amount="", accepted_category="", severity_rationale=row.get("proof_needed") or "",
            evidence_level=1, source_confirmed=False, reachable=False, manual_trace="", evidence_notes=row.get("proof_needed") or "",
            score_impact=int(score.get("impact", 0) or 0), score_reachability=int(score.get("reachability", 0) or 0), score_poc=int(score.get("poc_simplicity", 0) or 0), score_scope=int(score.get("scope_match", 0) or 0), score_novelty=int(score.get("novelty", 0) or 0), score_economics=int(score.get("economic_realism", 0) or 0), score_deductions=int(score.get("deductions", 0) or 0), score_rationale=score.get("rationale") or "scanner import",
            group_key=row.get("group_key") or row.get("dedupe_key"), chain_requirement=chain_requirements, tag=tags, reason="imported normalized scanner lead",
        )
        lead = default_lead(seq, ns)
        lead["source"]["tools"] = list(dict.fromkeys(str(t) for t in tools if t))
        if row.get("fingerprint"):
            lead["dedupe"]["scanner_fingerprint"] = row.get("fingerprint")
        if row.get("dedupe_key"):
            lead["dedupe"]["scanner_dedupe_key"] = row.get("dedupe_key")
        if row_status == "KILL":
            reason = "scanner-only"
            suppression = row.get("suppression") or {}
            lead["kill"] = {"reason": reason, "notes": suppression.get("reason") or "suppressed scanner noise", "killed_at": now()}
            lead["validation"]["verdict"] = "KILL"
        if row_status == "CHAIN_REQUIRED":
            lead["validation"]["verdict"] = "CHAIN_REQUIRED"
        db["leads"].append(lead)
        db["indexes"]["next_lead_sequence"] = seq + 1
        imported += 1
    touch(db)
    save_json(db_path, db)
    print(f"Imported {imported} scanner leads" + (f"; skipped {skipped} killed/suppressed rows" if skipped else ""))
    return 0


def add_artifact(args: argparse.Namespace) -> int:
    db_path = Path(args.database)
    db = load_json(db_path)
    seq = int(db["indexes"]["next_artifact_sequence"])
    aid = f"A-{seq:04d}"
    sha = None
    p = Path(args.path)
    if p.exists() and p.is_file():
        sha = hashlib.sha256(p.read_bytes()).hexdigest()
    artifact = {
        "id": aid,
        "type": args.type,
        "path": args.path,
        "tool": args.tool or "",
        "command": args.command or "",
        "created_at": now(),
        "summary": args.summary or "",
    }
    if sha:
        artifact["sha256"] = sha
    db["artifacts"].append(artifact)
    db["indexes"]["next_artifact_sequence"] = seq + 1
    touch(db)
    save_json(db_path, db)
    print(f"Added artifact {aid}: {args.path}")
    return 0


def list_leads(args: argparse.Namespace) -> int:
    db = load_json(Path(args.database))
    leads = db.get("leads", [])
    if args.status:
        leads = [l for l in leads if l.get("status") == args.status]
    if args.json:
        print(json.dumps(leads, indent=2))
        return 0
    print("| ID | Status | Severity | Bug class | Title | Location |")
    print("|---|---|---|---|---|---|")
    for l in leads:
        loc = (l.get("locations") or [{}])[0]
        location = ":".join(str(x) for x in [loc.get("file", "-"), loc.get("line_start", "-")] if x is not None)
        print(f"| {l['id']} | {l['status']} | {l.get('severity','UNKNOWN')} | `{l.get('bug_class','')}` | {l.get('title','')} | {location} |")
    return 0


def show_lead(args: argparse.Namespace) -> int:
    db = load_json(Path(args.database))
    lead = find_lead(db, args.lead_id)
    print(json.dumps(lead, indent=2))
    return 0


def show_metrics(args: argparse.Namespace) -> int:
    db_path = Path(args.database)
    db = load_json(db_path)
    recompute_metrics(db)
    by_status: dict[str, int] = {}
    by_bug_class: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for lead in db.get("leads", []):
        by_status[lead.get("status", "UNKNOWN")] = by_status.get(lead.get("status", "UNKNOWN"), 0) + 1
        by_bug_class[lead.get("bug_class", "unknown")] = by_bug_class.get(lead.get("bug_class", "unknown"), 0) + 1
        by_severity[lead.get("severity", "UNKNOWN")] = by_severity.get(lead.get("severity", "UNKNOWN"), 0) + 1
    metrics = {
        **db.get("metrics", {}),
        "by_status": dict(sorted(by_status.items())),
        "by_severity": dict(sorted(by_severity.items())),
        "by_bug_class": dict(sorted(by_bug_class.items())),
        "top_score_leads": [
            {
                "id": lead.get("id"),
                "status": lead.get("status"),
                "score": lead.get("score", {}).get("total", 0),
                "title": lead.get("title", ""),
            }
            for lead in sorted(db.get("leads", []), key=lambda l: l.get("score", {}).get("total", 0), reverse=True)[: args.limit]
        ],
    }
    if args.write:
        touch(db)
        save_json(db_path, db)
    if args.json:
        print(json.dumps(metrics, indent=2))
        return 0
    print(f"Lead count: {metrics.get('lead_count', 0)}")
    print(f"Report-ready/reported: {metrics.get('report_ready_count', 0)}")
    print(f"Killed: {metrics.get('kill_count', 0)}")
    print("\nBy status:")
    for status, count in metrics["by_status"].items():
        print(f"- {status}: {count}")
    print("\nTop scored leads:")
    for row in metrics["top_score_leads"]:
        print(f"- {row['id']} [{row['status']}] score={row['score']}: {row['title']}")
    return 0


def validate_business_rules(db: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    lead_ids = [l.get("id") for l in db.get("leads", [])]
    seen = set()
    for lid in lead_ids:
        if lid in seen:
            errors.append(f"duplicate lead id: {lid}")
        seen.add(lid)
    all_ids = set(lead_ids)
    artifact_ids = {a.get("id") for a in db.get("artifacts", [])}
    for lead in db.get("leads", []):
        lid = lead.get("id")
        status = lead.get("status")
        if status == "KILL" and not lead.get("kill", {}).get("reason"):
            errors.append(f"{lid}: KILL requires kill.reason")
        if status == "CHAIN_REQUIRED" and not lead.get("chain_requirements"):
            errors.append(f"{lid}: CHAIN_REQUIRED requires chain_requirements")
        if status == "DUPLICATE" and not lead.get("dedupe", {}).get("duplicate_of"):
            errors.append(f"{lid}: DUPLICATE requires dedupe.duplicate_of")
        if status in {"REPORT_READY", "REPORTED"}:
            q = lead.get("validation", {}).get("questions", {})
            if not all(q.values()):
                errors.append(f"{lid}: {status} requires all validation questions true")
            if lead.get("validation", {}).get("verdict") != "REPORT":
                errors.append(f"{lid}: {status} requires validation.verdict REPORT")
            if lead.get("evidence", {}).get("poc", {}).get("status") != "PASS":
                errors.append(f"{lid}: {status} requires evidence.poc.status PASS")
        dup = lead.get("dedupe", {}).get("duplicate_of")
        if dup == lid:
            errors.append(f"{lid}: duplicate_of cannot point to itself")
        if dup and dup not in all_ids:
            errors.append(f"{lid}: duplicate_of points to missing lead {dup}")
        for related in lead.get("dedupe", {}).get("related", []):
            if related not in all_ids:
                errors.append(f"{lid}: related lead missing: {related}")
        for link in lead.get("dedupe", {}).get("chain_links", []):
            target = link.get("lead_id")
            if target not in all_ids:
                errors.append(f"{lid}: chain link target missing: {target}")
        for ref in lead.get("source", {}).get("artifact_refs", []) + lead.get("evidence", {}).get("scanner_refs", []) + lead.get("evidence", {}).get("onchain_refs", []):
            if ref not in artifact_ids:
                errors.append(f"{lid}: artifact ref missing: {ref}")
    next_seq = db.get("indexes", {}).get("next_lead_sequence", 1)
    max_seq = max([l.get("sequence", 0) for l in db.get("leads", [])] or [0])
    if next_seq <= max_seq:
        errors.append(f"indexes.next_lead_sequence {next_seq} must be > max lead sequence {max_seq}")
    return errors


def validate_db(args: argparse.Namespace) -> int:
    db_path = Path(args.database)
    db = load_json(db_path)
    errors: list[str] = []
    try:
        import jsonschema  # type: ignore
        schema = load_json(Path(args.schema) if args.schema else schema_path())
        validator = jsonschema.Draft202012Validator(schema)
        for error in sorted(validator.iter_errors(db), key=lambda e: list(e.path)):
            loc = "/" + "/".join(str(x) for x in error.path)
            errors.append(f"schema {loc}: {error.message}")
    except ImportError:
        if not args.quiet:
            print("jsonschema not installed; running business-rule validation only", file=sys.stderr)
    errors.extend(validate_business_rules(db))
    if errors:
        print("Lead DB validation failed:")
        for err in errors:
            print(f"- {err}")
        return 1
    print(f"Lead DB validation passed: {db_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Web3 audit lead database CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init", help="initialize a lead database")
    sp.add_argument("database")
    sp.add_argument("--target", required=True)
    sp.add_argument("--protocol", action="append")
    sp.add_argument("--mode", default="bug-bounty", choices=["bug-bounty", "private-audit", "internal-review", "eval"])
    sp.add_argument("--repo", default=".")
    sp.add_argument("--chain-id", type=int, action="append")
    sp.add_argument("--notes")
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(func=init_db)

    sp = sub.add_parser("add", help="add a lead")
    sp.add_argument("database")
    sp.add_argument("--title", required=True)
    sp.add_argument("--bug-class", required=True)
    sp.add_argument("--status", choices=sorted(STATUSES), default="LEAD")
    sp.add_argument("--severity", choices=sorted(SEVERITIES), default="UNKNOWN")
    sp.add_argument("--confidence", choices=sorted(CONFIDENCES), default="UNKNOWN")
    sp.add_argument("--file")
    sp.add_argument("--contract")
    sp.add_argument("--function")
    sp.add_argument("--line", type=int)
    sp.add_argument("--chain-id", type=int)
    sp.add_argument("--address")
    sp.add_argument("--implementation")
    sp.add_argument("--origin", default="manual")
    sp.add_argument("--tool")
    sp.add_argument("--source-notes")
    sp.add_argument("--exploit-sentence")
    sp.add_argument("--attacker-capability")
    sp.add_argument("--precondition", action="append")
    sp.add_argument("--step", action="append")
    sp.add_argument("--invariant")
    sp.add_argument("--assertion-target")
    sp.add_argument("--expected-impact")
    sp.add_argument("--impact-type", default="unknown")
    sp.add_argument("--asset")
    sp.add_argument("--amount")
    sp.add_argument("--accepted-category")
    sp.add_argument("--severity-rationale")
    sp.add_argument("--evidence-level", type=int)
    sp.add_argument("--source-confirmed", action="store_true")
    sp.add_argument("--reachable", action="store_true")
    sp.add_argument("--manual-trace")
    sp.add_argument("--evidence-notes")
    sp.add_argument("--score-impact", type=int, default=0)
    sp.add_argument("--score-reachability", type=int, default=0)
    sp.add_argument("--score-poc", type=int, default=0)
    sp.add_argument("--score-scope", type=int, default=0)
    sp.add_argument("--score-novelty", type=int, default=0)
    sp.add_argument("--score-economics", type=int, default=0)
    sp.add_argument("--score-deductions", type=int, default=0)
    sp.add_argument("--score-rationale")
    sp.add_argument("--group-key")
    sp.add_argument("--chain-requirement", action="append")
    sp.add_argument("--tag", action="append")
    sp.add_argument("--reason")
    sp.set_defaults(func=add_lead)

    sp = sub.add_parser("list", help="list leads")
    sp.add_argument("database")
    sp.add_argument("--status", choices=sorted(STATUSES))
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=list_leads)

    sp = sub.add_parser("show", help="show one lead as JSON")
    sp.add_argument("database")
    sp.add_argument("lead_id")
    sp.set_defaults(func=show_lead)

    sp = sub.add_parser("metrics", help="show lead database metrics")
    sp.add_argument("database")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--write", action="store_true", help="persist recomputed metrics to the database")
    sp.add_argument("--limit", type=int, default=5, help="number of top scored leads to show")
    sp.set_defaults(func=show_metrics)

    sp = sub.add_parser("update-status", help="update lead status")
    sp.add_argument("database")
    sp.add_argument("lead_id")
    sp.add_argument("status", choices=sorted(STATUSES))
    sp.add_argument("--reason")
    sp.add_argument("--kill-reason", choices=sorted(KILL_REASONS))
    sp.add_argument("--chain-requirement", action="append")
    sp.set_defaults(func=update_status)

    sp = sub.add_parser("add-poc", help="attach PoC status/result")
    sp.add_argument("database")
    sp.add_argument("lead_id")
    sp.add_argument("--path", required=True)
    sp.add_argument("--command", required=True)
    sp.add_argument("--status", required=True, choices=["NONE", "PLANNED", "WRITTEN", "PASS", "FAIL", "BLOCKED"])
    sp.add_argument("--summary")
    sp.add_argument("--chain-id", type=int)
    sp.add_argument("--block-number", type=int)
    sp.add_argument("--rpc-env")
    sp.set_defaults(func=add_poc)

    sp = sub.add_parser("set-gate", help="set validation gate answers")
    sp.add_argument("database")
    sp.add_argument("lead_id")
    for flag in ["in-scope", "reachable", "normal-attacker", "normal-victim", "concrete-impact", "working-poc", "duplicate-intended-checked"]:
        dest = flag.replace("-", "_")
        group = sp.add_mutually_exclusive_group()
        group.add_argument(f"--{flag}", dest=dest, action="store_true")
        group.add_argument(f"--no-{flag}", dest=dest, action="store_false")
        sp.set_defaults(**{dest: None})
    sp.add_argument("--verdict", choices=["UNCHECKED", "REPORT", "CHAIN_REQUIRED", "KILL"])
    sp.add_argument("--promote", action="store_true")
    sp.add_argument("--notes")
    sp.set_defaults(func=set_gate)

    sp = sub.add_parser("import-scanner", help="import normalized scanner leads")
    sp.add_argument("database")
    sp.add_argument("normalized_json")
    sp.add_argument("--include-killed", action="store_true", help="also import KILL/suppressed scanner rows for auditability")
    sp.set_defaults(func=import_scanner)

    sp = sub.add_parser("add-artifact", help="add artifact reference")
    sp.add_argument("database")
    sp.add_argument("--type", required=True, choices=["xray", "entrypoints", "invariants", "scanner", "onchain", "poc", "report", "code-index", "audit-report-mining", "other"])
    sp.add_argument("--path", required=True)
    sp.add_argument("--tool")
    sp.add_argument("--command")
    sp.add_argument("--summary")
    sp.set_defaults(func=add_artifact)

    sp = sub.add_parser("validate", help="validate lead database")
    sp.add_argument("database")
    sp.add_argument("--schema")
    sp.add_argument("--quiet", action="store_true")
    sp.set_defaults(func=validate_db)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
