#!/usr/bin/env python3
"""Read-only on-chain probe for Web3 bounty validation.

Requires Foundry `cast` in PATH and an RPC URL. This tool never broadcasts.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path


IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"


@dataclass
class ProbeResult:
    address: str
    rpc_url_set: bool
    chain_id: str | None
    code_size_bytes: int | None
    native_balance_wei: str | None
    eip1967_implementation: str | None
    eip1967_admin: str | None
    eip1967_beacon: str | None
    owner: str | None
    admin_call: str | None
    paused: str | None
    total_supply: str | None
    total_assets: str | None
    token_balances: dict[str, str]
    errors: list[str]


def run_cast(args: list[str], rpc_url: str, timeout: int = 20) -> tuple[bool, str]:
    cmd = ["cast", *args, "--rpc-url", rpc_url]
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT, timeout=timeout).strip()
        return True, out
    except Exception as exc:  # noqa: BLE001 - command diagnostics are useful
        return False, str(exc)


def storage_to_address(word: str) -> str | None:
    w = word.strip().lower()
    if not w.startswith("0x"):
        return None
    if int(w, 16) == 0:
        return None
    return "0x" + w[-40:]


def code_size(code: str) -> int:
    c = code.strip()
    if c in {"", "0x"}:
        return 0
    if c.startswith("0x"):
        c = c[2:]
    return len(c) // 2


def try_call(address: str, signature: str, rpc_url: str) -> str | None:
    ok, out = run_cast(["call", address, signature], rpc_url)
    return out if ok else None


def main() -> int:
    ap = argparse.ArgumentParser(description="Read-only deployed contract probe")
    ap.add_argument("address")
    ap.add_argument("--rpc-url", default=None)
    ap.add_argument("--token", action="append", default=[], help="ERC20 token address to query balanceOf(target)")
    ap.add_argument("--json", dest="json_path")
    args = ap.parse_args()

    rpc_url = args.rpc_url or os.getenv("RPC_URL") or os.getenv("MAINNET_RPC_URL")
    errors: list[str] = []
    if not rpc_url:
        errors.append("RPC URL missing. Set RPC_URL or pass --rpc-url.")
        result = ProbeResult(args.address, False, None, None, None, None, None, None, None, None, None, None, None, {}, errors)
        print(json.dumps(asdict(result), indent=2))
        return 2

    ok, chain = run_cast(["chain-id"], rpc_url)
    chain_id = chain if ok else None
    if not ok:
        errors.append(f"chain-id failed: {chain}")

    ok, code = run_cast(["code", args.address], rpc_url)
    csize = code_size(code) if ok else None
    if not ok:
        errors.append(f"code failed: {code}")

    ok, bal = run_cast(["balance", args.address], rpc_url)
    native_balance = bal if ok else None
    if not ok:
        errors.append(f"balance failed: {bal}")

    def slot_addr(slot: str) -> str | None:
        ok_s, out_s = run_cast(["storage", args.address, slot], rpc_url)
        if not ok_s:
            errors.append(f"storage {slot} failed: {out_s}")
            return None
        return storage_to_address(out_s)

    token_balances: dict[str, str] = {}
    for token in args.token:
        ok_t, out_t = run_cast(["call", token, "balanceOf(address)(uint256)", args.address], rpc_url)
        if ok_t:
            token_balances[token] = out_t
        else:
            token_balances[token] = f"ERROR: {out_t}"

    result = ProbeResult(
        address=args.address,
        rpc_url_set=True,
        chain_id=chain_id,
        code_size_bytes=csize,
        native_balance_wei=native_balance,
        eip1967_implementation=slot_addr(IMPLEMENTATION_SLOT),
        eip1967_admin=slot_addr(ADMIN_SLOT),
        eip1967_beacon=slot_addr(BEACON_SLOT),
        owner=try_call(args.address, "owner()(address)", rpc_url),
        admin_call=try_call(args.address, "admin()(address)", rpc_url),
        paused=try_call(args.address, "paused()(bool)", rpc_url),
        total_supply=try_call(args.address, "totalSupply()(uint256)", rpc_url),
        total_assets=try_call(args.address, "totalAssets()(uint256)", rpc_url),
        token_balances=token_balances,
        errors=errors,
    )

    data = asdict(result)
    if args.json_path:
        Path(args.json_path).write_text(json.dumps(data, indent=2))

    print("# On-Chain Probe")
    print()
    print(f"address: `{result.address}`")
    print(f"chain_id: `{result.chain_id}`")
    print(f"code_size_bytes: `{result.code_size_bytes}`")
    print(f"native_balance_wei: `{result.native_balance_wei}`")
    print()
    print("## Proxy Slots")
    print(f"implementation: `{result.eip1967_implementation}`")
    print(f"admin: `{result.eip1967_admin}`")
    print(f"beacon: `{result.eip1967_beacon}`")
    print()
    print("## Common Calls")
    print(f"owner(): `{result.owner}`")
    print(f"admin(): `{result.admin_call}`")
    print(f"paused(): `{result.paused}`")
    print(f"totalSupply(): `{result.total_supply}`")
    print(f"totalAssets(): `{result.total_assets}`")
    if token_balances:
        print()
        print("## Token Balances")
        for token, tb in token_balances.items():
            print(f"- `{token}`: `{tb}`")
    if errors:
        print()
        print("## Errors")
        for err in errors:
            print(f"- {err}")
    print()
    print("Use this for validation only; still require a local/fork PoC for reporting.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
