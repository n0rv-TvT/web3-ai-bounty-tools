#!/usr/bin/env python3
"""Identify missing evidence needed to turn a hypothesis into a finding."""

from __future__ import annotations

from typing import Any


def has_poc_idea(h: dict[str, Any]) -> bool:
    poc = h.get("poc") or {}
    return bool(poc.get("idea") or poc.get("plan") or h.get("poc_idea") or h.get("minimal_poc_plan"))


def has_kill_condition(h: dict[str, Any]) -> bool:
    poc = h.get("poc") or {}
    return bool(h.get("kill_condition") or h.get("kill_if") or poc.get("kill_condition"))


def analyze_evidence_gaps(h: dict[str, Any]) -> dict[str, Any]:
    missing: list[str] = []
    if not h.get("file_path") or not h.get("function"):
        missing.append("specific file/function trace")
    if "requires validation" in str(h.get("affected_asset", "")).lower():
        missing.append("specific affected asset")
    if not (h.get("poc") or {}).get("assertion"):
        missing.append("working PoC with assertion")
    if not has_poc_idea(h):
        missing.append("minimal PoC idea")
    if not has_kill_condition(h):
        missing.append("kill condition")
    if "requires validation" in str((h.get("impact") or {}).get("type", "")).lower():
        missing.append("concrete impact class")
    if not h.get("external_evidence"):
        missing.append("source evidence snippet")
    if "hypothesis" not in str(h.get("severity_rationale", "")).lower():
        missing.append("uncertainty label")
    impact_text = str((h.get("impact") or {}).get("type", "")).lower() + " " + str(h.get("bug_class", "")).lower()
    return {"hypothesis_id": h.get("id") or h.get("lead_id"), "missing_evidence": missing, "economic_proof_needed": any(w in impact_text for w in ["stolen", "bad-debt", "inflation", "reward", "share", "oracle"]), "needs_context": bool(missing), "has_poc_idea": has_poc_idea(h), "has_kill_condition": has_kill_condition(h)}
