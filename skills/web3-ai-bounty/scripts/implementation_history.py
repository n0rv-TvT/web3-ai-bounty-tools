#!/usr/bin/env python3
"""Upgradeable-proxy implementation history mapping over mocked chain data."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from seedless_recon import ADMIN_SLOT, IMPLEMENTATION_SLOT, normalize_address, word_to_address


def classify_fact(value: Any, source: str) -> dict[str, Any]:
    confidence = "CONFIRMED" if source in {"storage", "event"} else ("LIKELY" if source == "source" else "UNVERIFIED")
    return {"value": value, "source": source, "confidence": confidence}


def storage_layout_mismatch(old_layout: list[dict[str, Any]], new_layout: list[dict[str, Any]]) -> bool:
    old_slots = {(str(v.get("slot")), str(v.get("label"))) for v in old_layout}
    new_slots = {(str(v.get("slot")), str(v.get("label"))) for v in new_layout}
    for slot, label in old_slots:
        if any(ns == slot and nl != label for ns, nl in new_slots):
            return True
    return False


def map_implementation_history(proxy_address: str, chain_data: dict[str, Any]) -> dict[str, Any]:
    proxy = normalize_address(proxy_address)
    storage = chain_data.get("storage", {})
    current_impl = word_to_address(storage.get(IMPLEMENTATION_SLOT, "0x" + "0" * 64))
    admin = word_to_address(storage.get(ADMIN_SLOT, "0x" + "0" * 64))
    upgrades = [e for e in chain_data.get("events", []) if e.get("event") in {"Upgraded", "ImplementationChanged"}]
    admin_events = [e for e in chain_data.get("events", []) if e.get("event") in {"AdminChanged", "OwnershipTransferred"}]
    previous = []
    for event in upgrades:
        impl = event.get("implementation") or event.get("newImplementation")
        if impl:
            previous.append(normalize_address(impl))
    risks: list[dict[str, Any]] = []
    layouts = chain_data.get("storage_layouts", {})
    for i in range(len(previous) - 1):
        if storage_layout_mismatch(layouts.get(previous[i], []), layouts.get(previous[i + 1], [])):
            risks.append({"type": "storage_layout_mismatch", "confidence": "LIKELY", "details": f"layout changed between {previous[i]} and {previous[i + 1]}"})
    impl_states = chain_data.get("implementation_state", {})
    for impl, state in impl_states.items():
        if state.get("initialized") is False or state.get("initializer_exposed") is True:
            risks.append({"type": "uninitialized_or_exposed_implementation", "confidence": "CONFIRMED", "implementation": normalize_address(impl)})
    return {
        "proxy": classify_fact(proxy, "input"),
        "current_implementation": classify_fact(current_impl, "storage") if current_impl else classify_fact(None, "unverified"),
        "admin": classify_fact(admin, "storage") if admin else classify_fact(None, "unverified"),
        "previous_implementations": [classify_fact(p, "event") for p in previous if p != current_impl],
        "upgrade_events": upgrades,
        "admin_changes": admin_events,
        "ownership_changes": [e for e in admin_events if e.get("event") == "OwnershipTransferred"],
        "timelock_or_governance_path": chain_data.get("governance_path", {"confidence": "UNVERIFIED", "value": None}),
        "risks": risks,
        "assumptions": chain_data.get("assumptions", []),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Map mocked implementation history")
    p.add_argument("proxy")
    p.add_argument("chain_data_json")
    args = p.parse_args(argv)
    print(json.dumps(map_implementation_history(args.proxy, json.loads(Path(args.chain_data_json).read_text(errors="replace"))), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
