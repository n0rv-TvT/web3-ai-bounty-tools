#!/usr/bin/env python3
"""Safe read-only seedless recon helpers backed by mockable chain clients."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Protocol


VERIFIED = "VERIFIED"
LIKELY = "LIKELY"
UNVERIFIED = "UNVERIFIED"
IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
READ_ONLY_ACTIONS = ["eth_getCode", "eth_getStorageAt", "eth_call", "eth_getLogs"]


class ReadOnlyChainClient(Protocol):
    def get_code(self, address: str) -> str: ...
    def get_storage_at(self, address: str, slot: str) -> str: ...
    def get_events(self, address: str) -> list[dict[str, Any]]: ...


class MockChainClient:
    def __init__(self, *, code: dict[str, str] | None = None, storage: dict[tuple[str, str], str] | None = None, events: dict[str, list[dict[str, Any]]] | None = None):
        self.code = {k.lower(): v for k, v in (code or {}).items()}
        self.storage = {(a.lower(), s): v for (a, s), v in (storage or {}).items()}
        self.events = {k.lower(): v for k, v in (events or {}).items()}

    def get_code(self, address: str) -> str:
        return self.code.get(address.lower(), "0x")

    def get_storage_at(self, address: str, slot: str) -> str:
        return self.storage.get((address.lower(), slot), "0x" + "0" * 64)

    def get_events(self, address: str) -> list[dict[str, Any]]:
        return self.events.get(address.lower(), [])


def normalize_address(address: str) -> str:
    if not re.fullmatch(r"0x[a-fA-F0-9]{40}", address or ""):
        raise SystemExit(f"Invalid address: {address}")
    return "0x" + address[2:].lower()


def word_to_address(word: str) -> str | None:
    if not word or word == "0x" or int(word, 16) == 0:
        return None
    return "0x" + word[-40:].lower()


def discover_from_known_address(address: str, client: ReadOnlyChainClient, *, user_confirmed_scope: bool = False) -> dict[str, Any]:
    target = normalize_address(address)
    code = client.get_code(target)
    impl = word_to_address(client.get_storage_at(target, IMPLEMENTATION_SLOT))
    admin = word_to_address(client.get_storage_at(target, ADMIN_SLOT))
    contracts = [{"address": target, "role": "proxy" if impl else "contract", "confidence": VERIFIED if code != "0x" else UNVERIFIED, "source": "mock_rpc"}]
    if impl:
        contracts.append({"address": impl, "role": "implementation", "confidence": VERIFIED if client.get_code(impl) != "0x" else LIKELY, "source": "eip1967_implementation_slot"})
    if admin:
        contracts.append({"address": admin, "role": "admin", "confidence": LIKELY, "source": "eip1967_admin_slot"})
    for event in client.get_events(target):
        if event.get("address"):
            contracts.append({"address": normalize_address(event["address"]), "role": event.get("role", "related"), "confidence": LIKELY, "source": "event"})
    return {"input": target, "read_only_actions": READ_ONLY_ACTIONS, "contracts": contracts, "scope_expansion_requires_confirmation": not user_confirmed_scope, "scope_expanded": bool(user_confirmed_scope)}


def mark_guess(address: str, role: str = "guessed") -> dict[str, str]:
    return {"address": normalize_address(address), "role": role, "confidence": UNVERIFIED, "source": "guess"}


def no_write_or_broadcast_actions_exist() -> bool:
    forbidden = [a for a in READ_ONLY_ACTIONS if any(x in a.lower() for x in ["send", "write", "broadcast", "transact"])]
    return not forbidden


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Seedless recon mock helper")
    p.add_argument("address")
    args = p.parse_args(argv)
    print(json.dumps({"error": "CLI requires a mock client in tests", "address": args.address}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
