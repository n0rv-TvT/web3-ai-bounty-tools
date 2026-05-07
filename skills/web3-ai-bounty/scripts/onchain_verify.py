#!/usr/bin/env python3
"""Read-only on-chain verifier with RPC, Sourcify, and explorer support.

Component 4 of the Web3 audit engine. This script never broadcasts
transactions, never stores RPC URLs/API keys in the output, and treats live
state as validation support rather than a finding.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "1.0.0"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"

SELECTORS = {
    "owner()(address)": "0x8da5cb5b",
    "admin()(address)": "0xf851a440",
    "implementation()(address)": "0x5c60da1b",
    "paused()(bool)": "0x5c975abb",
    "totalSupply()(uint256)": "0x18160ddd",
    "totalAssets()(uint256)": "0x01e1d114",
    "name()(string)": "0x06fdde03",
    "symbol()(string)": "0x95d89b41",
    "decimals()(uint8)": "0x313ce567",
    "balanceOf(address)(uint256)": "0x70a08231",
}

CHAIN_ENV = {
    1: "MAINNET_RPC_URL",
    10: "OPTIMISM_RPC_URL",
    56: "BSC_RPC_URL",
    100: "GNOSIS_RPC_URL",
    137: "POLYGON_RPC_URL",
    250: "FANTOM_RPC_URL",
    324: "ZKSYNC_RPC_URL",
    1101: "POLYGON_ZKEVM_RPC_URL",
    8453: "BASE_RPC_URL",
    42161: "ARBITRUM_RPC_URL",
    43114: "AVAX_RPC_URL",
    59144: "LINEA_RPC_URL",
    81457: "BLAST_RPC_URL",
    534352: "SCROLL_RPC_URL",
    11155111: "SEPOLIA_RPC_URL",
}

CHAIN_NAMES = {
    1: "ethereum-mainnet",
    10: "optimism",
    56: "bsc",
    100: "gnosis",
    137: "polygon",
    250: "fantom",
    324: "zksync-era",
    1101: "polygon-zkevm",
    8453: "base",
    42161: "arbitrum-one",
    43114: "avalanche-c-chain",
    59144: "linea",
    81457: "blast",
    534352: "scroll",
    11155111: "sepolia",
}

BLOCKSCOUT_EXPLORERS = {
    10: "https://optimism.blockscout.com/api",
    100: "https://gnosis.blockscout.com/api",
    324: "https://zksync.blockscout.com/api",
    1101: "https://zkevm.blockscout.com/api",
    8453: "https://base.blockscout.com/api",
    59144: "https://explorer.linea.build/api",
    81457: "https://blast.blockscout.com/api",
    534352: "https://scroll.blockscout.com/api",
}

COMMON_CALLS = [
    ("owner", "owner()(address)", "address"),
    ("admin", "admin()(address)", "address"),
    ("paused", "paused()(bool)", "bool"),
    ("totalSupply", "totalSupply()(uint256)", "uint256"),
    ("totalAssets", "totalAssets()(uint256)", "uint256"),
    ("name", "name()(string)", "string"),
    ("symbol", "symbol()(string)", "string"),
    ("decimals", "decimals()(uint8)", "uint256"),
]


class RpcError(Exception):
    pass


@dataclass
class RpcConfig:
    url: str | None
    source: str | None


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_address(address: str) -> str:
    a = (address or "").strip()
    if not re.fullmatch(r"0x[a-fA-F0-9]{40}", a):
        raise SystemExit(f"Invalid EVM address: {address}")
    return "0x" + a[2:].lower()


def is_zero_word(value: str | None) -> bool:
    if not value or not isinstance(value, str) or not value.startswith("0x"):
        return True
    try:
        return int(value, 16) == 0
    except Exception:
        return True


def storage_word_to_address(word: str | None) -> str | None:
    if is_zero_word(word):
        return None
    w = str(word).lower()
    return "0x" + w[-40:]


def code_size(code: str | None) -> int | None:
    if code is None:
        return None
    c = code.strip()
    if c in {"", "0x"}:
        return 0
    if c.startswith("0x"):
        c = c[2:]
    return len(c) // 2


def runtime_sha256(code: str | None) -> str | None:
    if not code or code == "0x":
        return None
    c = code[2:] if code.startswith("0x") else code
    try:
        return __import__("hashlib").sha256(bytes.fromhex(c)).hexdigest()
    except Exception:
        return None


def strip_0x(value: str) -> str:
    return value[2:] if value.startswith("0x") else value


def pad32_hex_address(address: str) -> str:
    return "0" * 24 + normalize_address(address)[2:]


def decode_uint(data: str | None) -> str | None:
    if not data or data == "0x":
        return None
    try:
        return str(int(data, 16))
    except Exception:
        return None


def decode_bool(data: str | None) -> bool | None:
    value = decode_uint(data)
    if value is None:
        return None
    return int(value) != 0


def decode_address(data: str | None) -> str | None:
    if is_zero_word(data):
        return None
    return "0x" + str(data).lower()[-40:]


def decode_string(data: str | None) -> str | None:
    if not data or data == "0x":
        return None
    h = strip_0x(data)
    try:
        # Some old tokens return bytes32 strings.
        if len(h) == 64:
            raw = bytes.fromhex(h).rstrip(b"\x00")
            return raw.decode("utf-8", errors="replace") if raw else None
        if len(h) < 128:
            return None
        offset = int(h[:64], 16) * 2
        length = int(h[offset : offset + 64], 16)
        raw = bytes.fromhex(h[offset + 64 : offset + 64 + length * 2])
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


def decode_call(data: str | None, typ: str) -> Any:
    if typ == "address":
        return decode_address(data)
    if typ == "bool":
        return decode_bool(data)
    if typ == "string":
        return decode_string(data)
    return decode_uint(data)


def json_http_post(url: str, payload: dict[str, Any], timeout: int) -> Any:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "web3-ai-bounty-onchain-verifier/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec - user-provided RPC is intentional
        return json.loads(resp.read().decode())


def http_get_json(url: str, timeout: int) -> tuple[int, Any, str | None]:
    req = urllib.request.Request(url, headers={"User-Agent": "web3-ai-bounty-onchain-verifier/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec - source verification endpoint is intentional
            body = resp.read().decode(errors="replace")
            try:
                return resp.status, json.loads(body), None
            except Exception:
                return resp.status, body, None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace") if exc.fp else ""
        return exc.code, body, str(exc)
    except Exception as exc:  # noqa: BLE001
        return 0, None, str(exc)


class JsonRpc:
    def __init__(self, url: str, timeout: int = 20) -> None:
        self.url = url
        self.timeout = timeout
        self.counter = 0

    def call(self, method: str, params: list[Any]) -> Any:
        self.counter += 1
        payload = {"jsonrpc": "2.0", "id": self.counter, "method": method, "params": params}
        data = json_http_post(self.url, payload, self.timeout)
        if "error" in data:
            raise RpcError(f"{method}: {data['error']}")
        return data.get("result")

    def chain_id(self) -> int:
        return int(self.call("eth_chainId", []), 16)

    def block_number(self) -> int:
        return int(self.call("eth_blockNumber", []), 16)

    def get_code(self, address: str, block: str = "latest") -> str:
        return self.call("eth_getCode", [address, block])

    def get_balance(self, address: str, block: str = "latest") -> str:
        return str(int(self.call("eth_getBalance", [address, block]), 16))

    def get_storage_at(self, address: str, slot: str, block: str = "latest") -> str:
        return self.call("eth_getStorageAt", [address, slot, block])

    def eth_call(self, to: str, data: str, block: str = "latest") -> str:
        return self.call("eth_call", [{"to": to, "data": data}, block])


def resolve_rpc(args: argparse.Namespace, chain_id_hint: int | None) -> RpcConfig:
    if args.rpc_url:
        return RpcConfig(args.rpc_url, "argument")
    if args.rpc_env and os.getenv(args.rpc_env):
        return RpcConfig(os.getenv(args.rpc_env), args.rpc_env)
    if chain_id_hint and CHAIN_ENV.get(chain_id_hint) and os.getenv(CHAIN_ENV[chain_id_hint]):
        env = CHAIN_ENV[chain_id_hint]
        return RpcConfig(os.getenv(env), env)
    if os.getenv("RPC_URL"):
        return RpcConfig(os.getenv("RPC_URL"), "RPC_URL")
    if os.getenv("MAINNET_RPC_URL"):
        return RpcConfig(os.getenv("MAINNET_RPC_URL"), "MAINNET_RPC_URL")
    return RpcConfig(None, None)


def safe_rpc(label: str, errors: list[str], fn) -> Any:  # type: ignore[no-untyped-def]
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001
        errors.append(f"{label} failed: {exc}")
        return None


def call_signature(rpc: JsonRpc, address: str, signature: str, typ: str, errors: list[str]) -> dict[str, Any]:
    selector = SELECTORS[signature]
    try:
        raw = rpc.eth_call(address, selector)
        return {"signature": signature, "ok": True, "raw": raw, "decoded": decode_call(raw, typ)}
    except Exception as exc:  # noqa: BLE001
        return {"signature": signature, "ok": False, "raw": None, "decoded": None, "error": str(exc)}


def balance_of(rpc: JsonRpc, token: str, holder: str) -> dict[str, Any]:
    data = SELECTORS["balanceOf(address)(uint256)"] + pad32_hex_address(holder)
    raw = rpc.eth_call(token, data)
    return {"token": token, "holder": holder, "ok": True, "raw": raw, "balance": decode_uint(raw)}


def detect_minimal_proxy(code: str | None) -> dict[str, Any] | None:
    if not code:
        return None
    c = code.lower()
    pattern = r"^0x363d3d373d3d3d363d73([a-f0-9]{40})5af43d82803e903d91602b57fd5bf3$"
    m = re.match(pattern, c)
    if not m:
        return None
    return {"pattern": "EIP-1167 minimal proxy", "implementation": "0x" + m.group(1)}


def probe_target(rpc: JsonRpc | None, address: str, chain_id_arg: int | None, tokens: list[str], block_tag: str) -> tuple[dict[str, Any], int | None, list[str]]:
    errors: list[str] = []
    if not rpc:
        return {
            "rpc_available": False,
            "chain_id": chain_id_arg,
            "chain_name": CHAIN_NAMES.get(chain_id_arg or -1),
            "block_number": None,
            "block_tag": block_tag,
            "address": address,
            "code_size_bytes": None,
            "runtime_sha256": None,
            "native_balance_wei": None,
            "proxy": {},
            "common_calls": {},
            "token_balances": [],
        }, chain_id_arg, ["RPC URL missing. Set RPC_URL, a chain-specific RPC env var, or pass --rpc-url."]

    chain_id = safe_rpc("eth_chainId", errors, rpc.chain_id) or chain_id_arg
    block_number = safe_rpc("eth_blockNumber", errors, rpc.block_number)
    code = safe_rpc("eth_getCode target", errors, lambda: rpc.get_code(address, block_tag))
    balance = safe_rpc("eth_getBalance target", errors, lambda: rpc.get_balance(address, block_tag))
    impl_word = safe_rpc("EIP-1967 implementation slot", errors, lambda: rpc.get_storage_at(address, IMPLEMENTATION_SLOT, block_tag))
    admin_word = safe_rpc("EIP-1967 admin slot", errors, lambda: rpc.get_storage_at(address, ADMIN_SLOT, block_tag))
    beacon_word = safe_rpc("EIP-1967 beacon slot", errors, lambda: rpc.get_storage_at(address, BEACON_SLOT, block_tag))
    implementation = storage_word_to_address(impl_word)
    admin = storage_word_to_address(admin_word)
    beacon = storage_word_to_address(beacon_word)
    minimal_proxy = detect_minimal_proxy(code)
    beacon_implementation = None
    if beacon:
        beacon_impl_raw = safe_rpc("beacon implementation()", errors, lambda: rpc.eth_call(beacon, SELECTORS["implementation()(address)"], block_tag))
        beacon_implementation = decode_address(beacon_impl_raw)
    effective_impl = implementation or beacon_implementation or (minimal_proxy or {}).get("implementation")
    impl_code = None
    if effective_impl:
        impl_code = safe_rpc("eth_getCode implementation", errors, lambda: rpc.get_code(effective_impl, block_tag))

    common: dict[str, Any] = {}
    for key, sig, typ in COMMON_CALLS:
        common[key] = call_signature(rpc, address, sig, typ, errors)

    token_balances = []
    for token in tokens:
        try:
            t = normalize_address(token)
            row = balance_of(rpc, t, address)
            token_meta = {
                "name": call_signature(rpc, t, "name()(string)", "string", errors).get("decoded"),
                "symbol": call_signature(rpc, t, "symbol()(string)", "string", errors).get("decoded"),
                "decimals": call_signature(rpc, t, "decimals()(uint8)", "uint256", errors).get("decoded"),
            }
            row["token_metadata"] = token_meta
            token_balances.append(row)
        except Exception as exc:  # noqa: BLE001
            token_balances.append({"token": token, "holder": address, "ok": False, "error": str(exc), "balance": None})

    proxy_kind = None
    if implementation:
        proxy_kind = "eip1967-proxy"
    elif beacon:
        proxy_kind = "eip1967-beacon-proxy"
    elif minimal_proxy:
        proxy_kind = "eip1167-minimal-proxy"

    target = {
        "rpc_available": True,
        "chain_id": chain_id,
        "chain_name": CHAIN_NAMES.get(chain_id or -1),
        "block_number": block_number,
        "block_tag": block_tag,
        "address": address,
        "code_size_bytes": code_size(code),
        "runtime_sha256": runtime_sha256(code),
        "native_balance_wei": balance,
        "proxy": {
            "detected": bool(proxy_kind),
            "kind": proxy_kind,
            "eip1967_implementation": implementation,
            "eip1967_admin": admin,
            "eip1967_beacon": beacon,
            "beacon_implementation": beacon_implementation,
            "minimal_proxy": minimal_proxy,
            "effective_implementation": effective_impl,
            "implementation_code_size_bytes": code_size(impl_code),
            "implementation_runtime_sha256": runtime_sha256(impl_code),
        },
        "common_calls": common,
        "token_balances": token_balances,
    }
    return target, chain_id, errors


def sourcify_fetch_one(chain_id: int, address: str, match_kind: str, timeout: int, base_url: str) -> dict[str, Any]:
    url = f"{base_url.rstrip('/')}/contracts/{match_kind}/{chain_id}/{address}/metadata.json"
    status, data, err = http_get_json(url, timeout)
    row: dict[str, Any] = {"provider": "sourcify", "match": match_kind, "url": url, "http_status": status, "verified": False}
    if err:
        row["error"] = err
    if status == 200 and isinstance(data, dict):
        comp_targets = (data.get("settings") or {}).get("compilationTarget") or {}
        contract_name = next(iter(comp_targets.values()), None) if isinstance(comp_targets, dict) else None
        sources = sorted(list((data.get("sources") or {}).keys())) if isinstance(data.get("sources"), dict) else []
        row.update({
            "verified": True,
            "contract_name": contract_name,
            "compiler_version": (data.get("compiler") or {}).get("version"),
            "language": data.get("language"),
            "source_file_count": len(sources),
            "source_files": sources[:200],
            "optimizer": ((data.get("settings") or {}).get("optimizer") or {}),
            "evm_version": (data.get("settings") or {}).get("evmVersion"),
            "metadata_hash": (data.get("settings") or {}).get("metadata", {}).get("bytecodeHash") if isinstance((data.get("settings") or {}).get("metadata"), dict) else None,
        })
    return row


def fetch_sourcify(chain_id: int | None, address: str, timeout: int, base_url: str, disabled: bool) -> dict[str, Any]:
    if disabled:
        return {"provider": "sourcify", "attempted": False, "reason": "disabled"}
    if not chain_id:
        return {"provider": "sourcify", "attempted": False, "reason": "chain_id unavailable"}
    full = sourcify_fetch_one(chain_id, address, "full_match", timeout, base_url)
    partial = sourcify_fetch_one(chain_id, address, "partial_match", timeout, base_url)
    best = full if full.get("verified") else partial if partial.get("verified") else None
    return {"provider": "sourcify", "attempted": True, "full_match": full, "partial_match": partial, "best": best}


def explorer_api_key(args: argparse.Namespace) -> str | None:
    if args.explorer_api_key:
        return args.explorer_api_key
    if args.explorer_api_key_env and os.getenv(args.explorer_api_key_env):
        return os.getenv(args.explorer_api_key_env)
    return os.getenv("ETHERSCAN_API_KEY") or os.getenv("EXPLORER_API_KEY")


def explorer_url_for(chain_id: int | None, args: argparse.Namespace) -> tuple[str | None, str]:
    if args.explorer_url:
        return args.explorer_url, args.explorer_kind
    if args.explorer_kind == "etherscan-v2" or (args.explorer_kind == "auto" and explorer_api_key(args)):
        return "https://api.etherscan.io/v2/api", "etherscan-v2"
    if chain_id in BLOCKSCOUT_EXPLORERS:
        return BLOCKSCOUT_EXPLORERS[chain_id], "blockscout"
    return None, args.explorer_kind


def normalize_explorer_source(result: dict[str, Any]) -> dict[str, Any]:
    source = str(result.get("SourceCode") or "")
    abi = str(result.get("ABI") or "")
    verified = bool(source.strip()) and source.strip() not in {"Contract source code not verified", ""}
    proxy_flag = str(result.get("Proxy") or "").lower() in {"1", "true", "yes"}
    implementation = result.get("Implementation") or None
    if isinstance(implementation, str) and implementation and re.fullmatch(r"0x[a-fA-F0-9]{40}", implementation):
        implementation = normalize_address(implementation)
    else:
        implementation = None
    source_file_count = None
    source_format = "single-file"
    if source.strip().startswith("{{") and source.strip().endswith("}}"):
        # Etherscan wraps standard JSON in an extra pair of braces.
        source_format = "etherscan-standard-json-wrapped"
    elif source.strip().startswith("{"):
        source_format = "json"
        try:
            parsed = json.loads(source)
            sources = parsed.get("sources") if isinstance(parsed, dict) else None
            if isinstance(sources, dict):
                source_file_count = len(sources)
        except Exception:
            pass
    return {
        "verified": verified,
        "contract_name": result.get("ContractName") or None,
        "compiler_version": result.get("CompilerVersion") or None,
        "optimization_used": result.get("OptimizationUsed") or None,
        "runs": result.get("Runs") or None,
        "evm_version": result.get("EVMVersion") or None,
        "license_type": result.get("LicenseType") or None,
        "proxy": proxy_flag,
        "implementation": implementation,
        "abi_available": bool(abi and abi != "Contract source code not verified"),
        "source_format": source_format,
        "source_file_count": source_file_count,
        "source_sha256": __import__("hashlib").sha256(source.encode()).hexdigest() if source else None,
        "constructor_arguments_present": bool(result.get("ConstructorArguments")),
    }


def fetch_explorer(chain_id: int | None, address: str, args: argparse.Namespace) -> dict[str, Any]:
    if args.skip_explorer:
        return {"provider": "explorer", "attempted": False, "reason": "disabled"}
    url, kind = explorer_url_for(chain_id, args)
    if not url:
        return {"provider": "explorer", "attempted": False, "reason": "no explorer URL/API key for chain"}
    key = explorer_api_key(args)
    params = {"module": "contract", "action": "getsourcecode", "address": address}
    if kind == "etherscan-v2" and chain_id:
        params["chainid"] = str(chain_id)
    if key:
        params["apikey"] = key
    full_url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    safe_url = re.sub(r"apikey=[^&]+", "apikey=<redacted>", full_url)
    status, data, err = http_get_json(full_url, args.timeout)
    row: dict[str, Any] = {"provider": kind, "attempted": True, "url": safe_url, "http_status": status, "verified": False}
    if err:
        row["error"] = err
    if isinstance(data, dict):
        row["api_status"] = data.get("status")
        row["api_message"] = data.get("message")
        result = data.get("result")
        if isinstance(result, list) and result and isinstance(result[0], dict):
            parsed = normalize_explorer_source(result[0])
            row.update(parsed)
        elif isinstance(result, str):
            row["api_result"] = result[:300]
    elif data:
        row["raw_prefix"] = str(data)[:300]
    return row


def source_summary(provider_rows: list[dict[str, Any]]) -> dict[str, Any]:
    verified = [r for r in provider_rows if r.get("verified")]
    best = verified[0] if verified else None
    return {
        "verified": bool(best),
        "best_provider": best.get("provider") if best else None,
        "best_match": best.get("match") if best else None,
        "contract_name": best.get("contract_name") if best else None,
        "compiler_version": best.get("compiler_version") if best else None,
        "proxy_flag": bool(best.get("proxy")) if best else False,
        "implementation": best.get("implementation") if best else None,
    }


def build_source_verification(chain_id: int | None, target: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    address = target["address"]
    impl = (target.get("proxy") or {}).get("effective_implementation")
    addresses = [("target", address)]
    if impl and impl != address:
        addresses.append(("implementation", impl))
    subjects = []
    for role, addr in addresses:
        sourcify = fetch_sourcify(chain_id, addr, args.timeout, args.sourcify_url, args.skip_sourcify)
        explorer = fetch_explorer(chain_id, addr, args)
        provider_rows = []
        if sourcify.get("best"):
            best = dict(sourcify["best"])
            best["provider"] = "sourcify"
            provider_rows.append(best)
        if explorer.get("attempted"):
            provider_rows.append(explorer)
        subjects.append({
            "role": role,
            "address": addr,
            "summary": source_summary(provider_rows),
            "sourcify": sourcify,
            "explorer": explorer,
        })
    return {"subjects": subjects}


def compare_expected(target: dict[str, Any], source: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    checks = []
    if args.expected_runtime_sha256:
        actual = target.get("runtime_sha256")
        checks.append({"name": "target-runtime-sha256", "expected": args.expected_runtime_sha256, "actual": actual, "pass": actual == args.expected_runtime_sha256})
    if args.expected_implementation:
        expected = normalize_address(args.expected_implementation)
        actual = (target.get("proxy") or {}).get("effective_implementation")
        checks.append({"name": "effective-implementation", "expected": expected, "actual": actual, "pass": actual == expected})
    if args.expected_contract_name:
        names = []
        for subj in source.get("subjects", []):
            name = ((subj.get("summary") or {}).get("contract_name"))
            if name:
                names.append(name)
        checks.append({"name": "verified-contract-name", "expected": args.expected_contract_name, "actual": names, "pass": args.expected_contract_name in names})
    return {"checks": checks, "all_passed": all(c.get("pass") for c in checks) if checks else None}


def validation_hints(target: dict[str, Any], source: dict[str, Any], comparisons: dict[str, Any]) -> dict[str, Any]:
    errors = []
    warnings = []
    positives = []
    if target.get("code_size_bytes") == 0:
        errors.append("Target address has no runtime bytecode at the selected block.")
    elif target.get("code_size_bytes"):
        positives.append("Target has deployed runtime bytecode.")
    proxy = target.get("proxy") or {}
    if proxy.get("detected"):
        positives.append(f"Proxy pattern detected: {proxy.get('kind')}.")
        if proxy.get("effective_implementation") and proxy.get("implementation_code_size_bytes") == 0:
            errors.append("Effective implementation has no runtime bytecode.")
    subjects = source.get("subjects", [])
    if not any(((s.get("summary") or {}).get("verified")) for s in subjects):
        warnings.append("No verified source found via configured Sourcify/explorer providers.")
    else:
        positives.append("Verified source found for at least one target/implementation subject.")
    if comparisons.get("all_passed") is False:
        errors.append("One or more expected deployed-code/source checks failed.")
    value_present = False
    try:
        value_present = int(target.get("native_balance_wei") or "0") > 0
    except Exception:
        pass
    for tb in target.get("token_balances") or []:
        try:
            value_present = value_present or int(tb.get("balance") or "0") > 0
        except Exception:
            pass
    common = target.get("common_calls") or {}
    if (common.get("totalAssets") or {}).get("decoded") not in {None, "0", 0}:
        value_present = True
    if value_present:
        positives.append("Live balance/value-at-risk signal is non-zero or totalAssets is available.")
    else:
        warnings.append("No non-zero value-at-risk observed from the requested balance probes.")
    return {"errors": errors, "warnings": warnings, "positives": positives, "reporting_note": "On-chain verification supports scope/reachability; a local or fork PoC with assertions is still required."}


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    address = normalize_address(args.address)
    chain_hint = args.chain_id
    rpc_cfg = resolve_rpc(args, chain_hint)
    rpc = JsonRpc(rpc_cfg.url, args.timeout) if rpc_cfg.url else None
    block_tag = str(args.block) if args.block is not None else "latest"
    target, chain_id, rpc_errors = probe_target(rpc, address, chain_hint, [normalize_address(t) for t in args.token], block_tag)
    source = build_source_verification(chain_id, target, args)
    comparisons = compare_expected(target, source, args)
    hints = validation_hints(target, source, comparisons)
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "target": target,
        "rpc": {"url_set": bool(rpc_cfg.url), "url_source": rpc_cfg.source, "url_value_stored": False, "errors": rpc_errors},
        "source_verification": source,
        "comparisons": comparisons,
        "validation_hints": hints,
        "safety": {"read_only": True, "broadcasts_transactions": False, "stores_rpc_url_or_api_key": False},
    }
    return report


def print_markdown(report: dict[str, Any]) -> None:
    target = report["target"]
    proxy = target.get("proxy") or {}
    print("# On-Chain Verification")
    print()
    print(f"Address: `{target['address']}`")
    print(f"Chain: `{target.get('chain_id')}` ({target.get('chain_name') or 'unknown'})")
    print(f"Block: `{target.get('block_number')}` tag=`{target.get('block_tag')}`")
    print(f"Code size: `{target.get('code_size_bytes')}` bytes")
    print(f"Runtime sha256: `{target.get('runtime_sha256')}`")
    print(f"Native balance wei: `{target.get('native_balance_wei')}`")
    print()
    print("## Proxy")
    print(f"Detected: `{proxy.get('detected')}` kind=`{proxy.get('kind')}`")
    print(f"Implementation: `{proxy.get('effective_implementation')}`")
    print(f"Admin: `{proxy.get('eip1967_admin')}`")
    print(f"Beacon: `{proxy.get('eip1967_beacon')}`")
    print()
    print("## Verified Source")
    for subj in report.get("source_verification", {}).get("subjects", []):
        summary = subj.get("summary") or {}
        print(f"- {subj.get('role')} `{subj.get('address')}`: verified=`{summary.get('verified')}` provider=`{summary.get('best_provider')}` contract=`{summary.get('contract_name')}` compiler=`{summary.get('compiler_version')}`")
    print()
    print("## Common Calls")
    for key, row in (target.get("common_calls") or {}).items():
        if row.get("ok") and row.get("decoded") is not None:
            print(f"- {key}: `{row.get('decoded')}`")
    if target.get("token_balances"):
        print()
        print("## Token Balances")
        for tb in target["token_balances"]:
            meta = tb.get("token_metadata") or {}
            print(f"- `{tb.get('token')}` {meta.get('symbol') or ''}: `{tb.get('balance')}`")
    hints = report.get("validation_hints") or {}
    print()
    print("## Validation Hints")
    for item in hints.get("positives", []):
        print(f"+ {item}")
    for item in hints.get("warnings", []):
        print(f"! {item}")
    for item in hints.get("errors", []):
        print(f"- {item}")
    if report.get("rpc", {}).get("errors"):
        print()
        print("## RPC Errors")
        for err in report["rpc"]["errors"]:
            print(f"- {err}")
    print()
    print("Read-only validation only. A local/fork PoC with assertions is still required before reporting.")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Read-only on-chain verifier with RPC, Sourcify, and explorer support")
    ap.add_argument("address", help="target contract/proxy address")
    ap.add_argument("--chain-id", type=int, help="chain id hint; required for source verification when no RPC is available")
    ap.add_argument("--rpc-url", help="RPC URL; never written to output")
    ap.add_argument("--rpc-env", help="environment variable containing RPC URL")
    ap.add_argument("--block", type=int, help="block number for read-only RPC state")
    ap.add_argument("--token", action="append", default=[], help="ERC20 token address to query balanceOf(target)")
    ap.add_argument("--json", dest="json_path", help="write verification report JSON")
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--skip-sourcify", action="store_true")
    ap.add_argument("--sourcify-url", default="https://repo.sourcify.dev")
    ap.add_argument("--skip-explorer", action="store_true")
    ap.add_argument("--explorer-url", help="custom Etherscan/Blockscout-compatible API URL")
    ap.add_argument("--explorer-kind", default="auto", choices=["auto", "etherscan-v2", "blockscout", "etherscan"])
    ap.add_argument("--explorer-api-key", help="explorer API key; never written to output")
    ap.add_argument("--explorer-api-key-env", help="environment variable containing explorer API key")
    ap.add_argument("--expected-implementation", help="expected effective implementation address")
    ap.add_argument("--expected-contract-name", help="expected verified contract name")
    ap.add_argument("--expected-runtime-sha256", help="expected target runtime sha256")
    ap.add_argument("--strict-exit", action="store_true", help="exit non-zero if validation hints contain errors")
    return ap


def main() -> int:
    args = build_parser().parse_args()
    report = build_report(args)
    if args.json_path:
        out = Path(args.json_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2) + "\n")
    print_markdown(report)
    if args.strict_exit and report.get("validation_hints", {}).get("errors"):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
