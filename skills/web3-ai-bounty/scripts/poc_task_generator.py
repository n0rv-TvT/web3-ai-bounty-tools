#!/usr/bin/env python3
"""Generate minimal Foundry confirmation-task plans from hypotheses."""

from __future__ import annotations

from typing import Any


def task_type_for(h: dict[str, Any]) -> str:
    text = (str(h.get("bug_class") or "") + " " + str((h.get("impact") or {}).get("type", "")) + " " + str(h.get("exploit_scenario") or "")).lower()
    bug = str(h.get("bug_class") or "").lower()
    if "access" in text or "privileged" in text or "unauthorized" in text:
        return "unauthorized action PoC"
    if "reward" in bug:
        return "reward extraction PoC"
    if "round" in bug or "precision" in bug or "decimal" in bug:
        return "rounding/precision PoC"
    if "revert" in bug or "external component" in text or "callback" in bug:
        return "external component revert PoC"
    if "oracle" in bug or "price" in bug:
        return "oracle manipulation PoC"
    if "signature" in bug or "replay" in bug or "nonce" in bug or "domain" in bug:
        return "signature replay PoC"
    if "initializ" in bug or "upgrade" in bug or "takeover" in bug:
        return "initialization/takeover PoC"
    if "queue" in bug or "progress" in bug or "loop" in bug:
        return "queue/progress PoC"
    if "patch" in text or h.get("patch_pair_id"):
        return "patched-version regression PoC"
    if "share" in text or "accounting" in text or "erc4626" in text:
        return "share/accounting manipulation PoC"
    return "business-logic confirmation PoC"


def foundry_poc_task(h: dict[str, Any], missing_evidence: list[str] | None = None) -> dict[str, Any]:
    contract = h.get("contract") or "Target"
    function = h.get("function") or "targetFunction"
    bug_class = str(h.get("bug_class") or "business_logic").replace("-", "_")
    test_name = f"test_confirm_{contract}_{function}_{bug_class}".replace(".", "_")
    task_type = task_type_for(h)
    return {
        "framework": "Foundry",
        "task_type": task_type,
        "actors": ["attacker", "victim", "protocol"],
        "setup": [f"deploy or instantiate {contract}", "fund attacker/victim/control actors", "establish honest baseline state"],
        "attack_steps": [f"call {contract}.{function} through the suspected path", "exercise boundary/order condition from the hypothesis", "record balances/accounting before and after"],
        "assertions": ["assert exact attacker gain, victim/protocol loss, bad debt, frozen funds, or unauthorized state change", "assert honest control path still works"],
        "expected_failure": "PoC should fail to prove impact if any missing precondition is false",
        "kill_condition": h.get("kill_condition") or (h.get("poc") or {}).get("kill_condition") or "kill if normal attacker cannot reach the path or no concrete asset/state impact can be asserted",
        "suggested_test_name": test_name,
        "missing_evidence": missing_evidence or [],
        "does_not_execute": True,
        "report_ready": False,
        "counts_as_finding": False,
    }
