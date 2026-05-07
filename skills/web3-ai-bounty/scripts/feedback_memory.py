#!/usr/bin/env python3
"""Append-only reviewer feedback memory for Web3 audit outcomes."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any


OUTCOMES = {"ACCEPTED", "REJECTED", "DOWNGRADED", "DUPLICATE", "INFORMATIVE", "NEEDS_MORE_INFO"}
SPECULATIVE = ["could potentially", "potential", "possibly", "might", "may", "likely"]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_memory(path: Path) -> dict[str, Any]:
    """Load append-only feedback memory JSON, or initialize empty memory if absent."""

    if not path.exists():
        return {"schema_version": "1.0.0", "entries": []}
    data = json.loads(path.read_text(errors="replace"))
    if not isinstance(data, dict):
        raise SystemExit(f"Feedback memory root must be an object: {path}")
    data.setdefault("schema_version", "1.0.0")
    data.setdefault("entries", [])
    return data


def save_memory(path: Path, memory: dict[str, Any]) -> None:
    """Persist append-only memory JSON."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(memory, indent=2, sort_keys=False) + "\n")


def normalize_outcome(outcome: str) -> str:
    value = str(outcome).upper().replace(" ", "_")
    if value not in OUTCOMES:
        raise SystemExit(f"Invalid reviewer outcome: {outcome}")
    return value


def word_boundary_pattern(phrase: str) -> re.Pattern[str]:
    escaped = r"\s+".join(re.escape(part) for part in phrase.split())
    return re.compile(rf"(?<![A-Za-z0-9]){escaped}(?![A-Za-z0-9])", re.IGNORECASE)


def phrase_matches_text(phrase: str, text: str) -> bool:
    return bool(word_boundary_pattern(phrase).search(text or ""))


def lead_bug_class(lead: dict[str, Any]) -> str:
    return str(lead.get("vulnerability_class") or lead.get("bug_class") or "unknown")


def lead_signature(lead: dict[str, Any]) -> str:
    loc = (lead.get("locations") or [{}])[0] if isinstance(lead.get("locations"), list) else {}
    parts = [
        lead_bug_class(lead),
        str(lead.get("endpoint") or ""),
        str((lead.get("dedupe") or {}).get("group_key") or ""),
        str(loc.get("contract") or lead.get("contract") or ""),
        str(loc.get("function") or lead.get("function") or ""),
    ]
    return " | ".join(" ".join(p.lower().split()) for p in parts if p)


def parse_usd_amounts(text: str) -> list[Decimal]:
    amounts = []
    for match in re.finditer(r"(?:\$\s*([0-9][0-9,]*(?:\.[0-9]+)?)|([0-9][0-9,]*(?:\.[0-9]+)?)\s*USD)", text or "", re.I):
        raw = next(g for g in match.groups() if g)
        amounts.append(Decimal(raw.replace(",", "")))
    return amounts


def extract_rejection_patterns(triager_reason: str, original_report: str) -> list[str]:
    text = f"{triager_reason}\n{original_report}"
    patterns = [p for p in SPECULATIVE if phrase_matches_text(p, text)]
    quoted = re.findall(r"['\"]([^'\"]{4,80})['\"]", triager_reason or "")
    return sorted(set(patterns + quoted))


def extract_downgrade_reasons(triager_reason: str, outcome: str) -> list[str]:
    if normalize_outcome(outcome) != "DOWNGRADED":
        return []
    reason = " ".join((triager_reason or "").split())
    return [reason] if reason else ["severity downgraded by reviewer"]


def extract_accepted_impact_language(triager_reason: str, original_report: str, outcome: str) -> str:
    if normalize_outcome(outcome) != "ACCEPTED":
        return ""
    for line in (original_report or "").splitlines():
        if "$" in line or "USD" in line.upper() or "bad debt" in line.lower():
            return line.strip()
    return (triager_reason or "").strip()


def stable_feedback_id(entry: dict[str, Any]) -> str:
    raw = json.dumps({k: entry.get(k) for k in ["finding_id", "reviewer_decision", "reason", "timestamp"]}, sort_keys=True)
    return "fb_" + hashlib.sha256(raw.encode()).hexdigest()[:16]


def build_feedback_entry(
    *,
    lead: dict[str, Any],
    outcome: str,
    triager_reason: str,
    original_report: str,
    severity_reported: str | None = None,
    severity_accepted: str | None = None,
    usd_impact_reported: Decimal | None = None,
    usd_impact_accepted: Decimal | None = None,
    duplicate_of: str | None = None,
    submission_date: str | None = None,
) -> dict[str, Any]:
    decision = normalize_outcome(outcome)
    entry = {
        "finding_id": str(lead.get("id") or lead.get("finding_id") or "unknown"),
        "project_type": str(lead.get("project_type") or lead.get("protocol_type") or "unknown"),
        "vulnerability_class": lead_bug_class(lead),
        "signature": lead_signature(lead),
        "original_severity": severity_reported or str(lead.get("severity") or "UNKNOWN"),
        "revised_severity": severity_accepted or severity_reported or str(lead.get("severity") or "UNKNOWN"),
        "original_claim": original_report[:500],
        "reviewer_decision": decision,
        "reason": triager_reason,
        "accepted_fix": "",
        "duplicate_of": duplicate_of or "",
        "usd_impact_reported": str(usd_impact_reported or ""),
        "usd_impact_accepted": str(usd_impact_accepted or ""),
        "rejection_patterns": extract_rejection_patterns(triager_reason, original_report) if decision in {"REJECTED", "NEEDS_MORE_INFO"} else [],
        "downgrade_reasons": extract_downgrade_reasons(triager_reason, decision),
        "accepted_template": extract_accepted_impact_language(triager_reason, original_report, decision),
        "confidence_adjustment": "0",
        "reusable_lesson": f"{decision} from {lead.get('id', 'unknown')}: {triager_reason}",
        "timestamp": submission_date or utc_now(),
    }
    entry["feedback_id"] = stable_feedback_id(entry)
    return entry


def _append(memory_path: Path, entry: dict[str, Any]) -> dict[str, Any]:
    memory = load_memory(memory_path)
    memory.setdefault("entries", []).append(entry)
    save_memory(memory_path, memory)
    return entry


def record_reviewer_feedback(memory_path: Path, *, lead: dict[str, Any], outcome: str, triager_reason: str, original_report: str, **kwargs: Any) -> dict[str, Any]:
    return _append(memory_path, build_feedback_entry(lead=lead, outcome=outcome, triager_reason=triager_reason, original_report=original_report, **kwargs))


def record_false_positive(memory_path: Path, *, lead: dict[str, Any], reason: str, original_report: str = "") -> dict[str, Any]:
    return record_reviewer_feedback(memory_path, lead=lead, outcome="REJECTED", triager_reason=reason, original_report=original_report)


def record_false_negative(memory_path: Path, *, lead: dict[str, Any], reason: str, original_report: str = "") -> dict[str, Any]:
    return record_reviewer_feedback(memory_path, lead=lead, outcome="NEEDS_MORE_INFO", triager_reason=reason, original_report=original_report)


def record_confirmed_finding(memory_path: Path, *, lead: dict[str, Any], reason: str, original_report: str) -> dict[str, Any]:
    return record_reviewer_feedback(memory_path, lead=lead, outcome="ACCEPTED", triager_reason=reason, original_report=original_report)


def record_severity_change(memory_path: Path, *, lead: dict[str, Any], original_severity: str, revised_severity: str, reason: str, original_report: str = "") -> dict[str, Any]:
    return record_reviewer_feedback(memory_path, lead=lead, outcome="DOWNGRADED", triager_reason=reason, original_report=original_report, severity_reported=original_severity, severity_accepted=revised_severity)


def signature_matches(stored_signature: str, future_signature: str) -> bool:
    return bool(stored_signature and future_signature and (stored_signature == future_signature or stored_signature in future_signature or future_signature in stored_signature))


def confidence_delta_for_entry(entry: dict[str, Any], *, future_lead: dict[str, Any], future_report: str) -> Decimal:
    same_class = entry.get("vulnerability_class") == lead_bug_class(future_lead)
    if not same_class:
        return Decimal("0")
    outcome = entry.get("reviewer_decision")
    if outcome == "DUPLICATE" and signature_matches(str(entry.get("signature") or ""), lead_signature(future_lead)):
        return Decimal("-0.5")
    if outcome == "REJECTED" and any(phrase_matches_text(p, future_report) for p in entry.get("rejection_patterns") or []):
        return Decimal("-0.2")
    if outcome == "DOWNGRADED":
        return Decimal("-0.1")
    if outcome == "ACCEPTED" and entry.get("accepted_template"):
        return Decimal("0.1")
    return Decimal("0")


def build_memory_hit(entry: dict[str, Any], *, future_lead: dict[str, Any], future_report: str) -> dict[str, Any] | None:
    delta = confidence_delta_for_entry(entry, future_lead=future_lead, future_report=future_report)
    if delta == 0:
        return None
    lesson = str(entry.get("reusable_lesson") or entry.get("reason") or "memory hit")
    return {
        "source_lead_id": entry.get("finding_id"),
        "outcome": entry.get("reviewer_decision"),
        "lesson": lesson,
        "confidence_adjustment": str(delta),
        "warning": lesson if delta < 0 else "",
        "accepted_template": entry.get("accepted_template") if delta > 0 else "",
    }


def query_similar_past_cases(memory: dict[str, Any], *, future_lead: dict[str, Any], future_report: str) -> list[dict[str, Any]]:
    return [hit for entry in memory.get("entries", []) if (hit := build_memory_hit(entry, future_lead=future_lead, future_report=future_report))]


def adjust_confidence_from_memory(memory: dict[str, Any], *, future_lead: dict[str, Any], future_report: str) -> dict[str, Any]:
    hits = query_similar_past_cases(memory, future_lead=future_lead, future_report=future_report)
    total = sum((Decimal(str(hit["confidence_adjustment"])) for hit in hits), Decimal("0"))
    return {"total_adjustment": str(total), "memory_hits": hits, "explanation": [hit["lesson"] for hit in hits]}


def suggest_accepted_language(memory: dict[str, Any], *, future_lead: dict[str, Any]) -> list[str]:
    return [str(e["accepted_template"]) for e in memory.get("entries", []) if e.get("reviewer_decision") == "ACCEPTED" and e.get("vulnerability_class") == lead_bug_class(future_lead) and e.get("accepted_template")]


def flag_repeated_bad_pattern(memory: dict[str, Any], *, future_lead: dict[str, Any], future_report: str) -> list[str]:
    return [hit["lesson"] for hit in query_similar_past_cases(memory, future_lead=future_lead, future_report=future_report) if Decimal(str(hit["confidence_adjustment"])) < 0]


def query_feedback_memory(memory: dict[str, Any], *, future_lead: dict[str, Any], future_report: str) -> dict[str, Any]:
    adjusted = adjust_confidence_from_memory(memory, future_lead=future_lead, future_report=future_report)
    warnings = [hit["warning"] for hit in adjusted["memory_hits"] if hit.get("warning")]
    return {
        "lead_id": future_lead.get("id"),
        "bug_class": lead_bug_class(future_lead),
        "memory_hits": adjusted["memory_hits"],
        "total_adjustment": adjusted["total_adjustment"],
        "warnings": warnings,
        "accepted_templates": suggest_accepted_language(memory, future_lead=future_lead),
        "explanation": adjusted["explanation"],
    }


def query_feedback_memory_file(memory_path: Path, *, future_lead: dict[str, Any], future_report: str) -> dict[str, Any]:
    return query_feedback_memory(load_memory(memory_path), future_lead=future_lead, future_report=future_report)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Query feedback memory")
    p.add_argument("memory")
    args = p.parse_args(argv)
    print(json.dumps(load_memory(Path(args.memory)), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
