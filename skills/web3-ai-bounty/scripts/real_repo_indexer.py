#!/usr/bin/env python3
"""Source-only real Solidity/EVM repository indexer.

The indexer treats project content as untrusted data. It reads only detector-safe
Solidity/config files via ``solidity_fixture_indexer.iter_solidity_files`` and
never reads expected findings, reports, issues, README hints, scripts, broadcast
artifacts, node_modules, or lib dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
from pathlib import Path
from typing import Any

from prompt_injection_guard import scan_text
from solidity_fixture_indexer import index_project


STATE_RE = re.compile(r"^\s*(?P<type>mapping\s*\([^;]+\)|[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?)\s+(?P<attrs>(?:public|private|internal|constant|immutable|override|virtual|\s)+)?\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:=[^;]+)?;", re.M)
STRUCT_RE = re.compile(r"\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
ENUM_RE = re.compile(r"\benum\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
EVENT_RE = re.compile(r"\bevent\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
ERROR_RE = re.compile(r"\berror\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(|;)")
IMPORT_RE = re.compile(r"^\s*import\s+(?P<body>[^;]+);", re.M)
MODIFIER_RE = re.compile(r"\bmodifier\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*\{")
LOW_LEVEL_RE = re.compile(r"\.(call|delegatecall|staticcall)\s*(?:\{|\()")
TOKEN_TRANSFER_RE = re.compile(r"\.(transfer|transferFrom|safeTransfer|safeTransferFrom)\s*\(")
ETH_TRANSFER_RE = re.compile(r"\.(transfer|send)\s*\(|\.call\s*\{\s*value\s*:")
ORACLE_RE = re.compile(r"\b(latestRoundData|getPrice|getAssetPrice|getRSETHPrice|price\s*\(|answer)\b")
SIGNATURE_RE = re.compile(r"\b(ecrecover|ECDSA|recover\s*\(|signature|DOMAIN_SEPARATOR|permit|nonces?)\b", re.I)
PROOF_RE = re.compile(r"\b(verify|proof|merkle|root|leaf|inclusion)\b", re.I)
INIT_RE = re.compile(r"\b(initializer|reinitializer|initialize|_disableInitializers|upgradeTo|upgradeToAndCall|TransparentUpgradeableProxy|UUPSUpgradeable)\b")
LOOP_RE = re.compile(r"\b(for|while)\s*\(")
ROLE_RE = re.compile(r"\b(onlyOwner|onlyRole|hasRole|DEFAULT_ADMIN_ROLE|owner\s*\(|admin|governance|keeper|operator|manager|require\s*\(\s*msg\.sender)\b", re.I)
ACCOUNTING_RE = re.compile(r"\b(totalSupply|totalAssets|shares?|balanceOf|debt|collateral|reward|index|acc|queue|withdrawal|reserve|liquidity|strategy)\b", re.I)
EXTERNAL_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:\s*\([^;{}\n]*\))?)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def repo_id_for(root: Path) -> str:
    return root.name + "-" + hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:8]


def line_for(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def row_id(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:12]


def extract_imports(file_path: str, text: str) -> list[dict[str, Any]]:
    return [{"file": file_path, "import": m.group("body").strip(), "line": line_for(text, m.start())} for m in IMPORT_RE.finditer(text)]


def extract_state(file_path: str, contract: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    body = contract.get("body", "")
    states = []
    for m in STATE_RE.finditer(body):
        typ = m.group("type")
        states.append({
            "file": file_path,
            "contract": contract["name"],
            "name": m.group("name"),
            "type": typ.strip(),
            "visibility": (m.group("attrs") or "").strip(),
            "is_mapping": typ.strip().startswith("mapping"),
            "line": contract.get("start_line", 1) + body.count("\n", 0, m.start()),
        })
    structs = [{"file": file_path, "contract": contract["name"], "name": m.group(1)} for m in STRUCT_RE.finditer(body)]
    enums = [{"file": file_path, "contract": contract["name"], "name": m.group(1)} for m in ENUM_RE.finditer(body)]
    events = [{"file": file_path, "contract": contract["name"], "name": m.group(1)} for m in EVENT_RE.finditer(body)]
    errors = [{"file": file_path, "contract": contract["name"], "name": m.group(1)} for m in ERROR_RE.finditer(body)]
    return states, structs, enums, events, errors


def fn_row(file_path: str, contract: dict[str, Any], fn: dict[str, Any]) -> dict[str, Any]:
    body = fn.get("body", "")
    signature = fn.get("signature", "")
    visibility = fn.get("visibility") or "public-default"
    payable = bool(re.search(r"\bpayable\b", signature))
    state_mutating = visibility in {"external", "public", "public-default"} and not re.search(r"\b(view|pure)\b", signature)
    return {
        "id": row_id(file_path, contract["name"], fn["name"], fn.get("start_line")),
        "file": file_path,
        "contract": contract["name"],
        "name": fn["name"],
        "visibility": visibility,
        "modifiers": fn.get("modifiers", []),
        "signature": signature,
        "start_line": fn.get("start_line"),
        "end_line": fn.get("end_line"),
        "payable": payable,
        "state_mutating": state_mutating,
        "body": body,
        "contains_loop": bool(LOOP_RE.search(body)),
        "contains_external_call": bool(LOW_LEVEL_RE.search(body) or EXTERNAL_CALL_RE.search(body)),
        "contains_token_transfer": bool(TOKEN_TRANSFER_RE.search(body)),
        "contains_eth_transfer": bool(ETH_TRANSFER_RE.search(body)),
        "contains_role_check": bool(ROLE_RE.search(body) or any(re.search(r"owner|role|admin|keeper|manager", m, re.I) for m in fn.get("modifiers", []))),
        "contains_accounting_signal": bool(ACCOUNTING_RE.search(body + " " + fn.get("name", ""))),
    }


def extract_occurrences(file_path: str, contract: dict[str, Any], fn: dict[str, Any], pattern: re.Pattern[str], kind: str) -> list[dict[str, Any]]:
    body = fn.get("body", "")
    rows = []
    for m in pattern.finditer(body):
        rows.append({
            "id": row_id(kind, file_path, contract["name"], fn["name"], m.start()),
            "kind": kind,
            "file": file_path,
            "contract": contract["name"],
            "function": fn["name"],
            "line": fn.get("start_line", 1) + body.count("\n", 0, m.start()),
            "text": m.group(0)[:160],
        })
    return rows


def upgrade_occurrences(file_path: str, contract: dict[str, Any], fn: dict[str, Any]) -> list[dict[str, Any]]:
    rows = extract_occurrences(file_path, contract, fn, INIT_RE, "upgrade_or_initializer")
    signature = fn.get("signature", "")
    name = fn.get("name", "")
    if INIT_RE.search(signature + " " + name) and not rows:
        rows.append({
            "id": row_id("upgrade_or_initializer", file_path, contract["name"], name, fn.get("start_line")),
            "kind": "upgrade_or_initializer",
            "file": file_path,
            "contract": contract["name"],
            "function": name,
            "line": fn.get("start_line", 1),
            "text": signature[:160] or name,
        })
    return rows


def risk_signals_for_function(file_path: str, contract: dict[str, Any], fn: dict[str, Any]) -> list[dict[str, Any]]:
    body = fn.get("body", "")
    name = fn.get("name", "")
    signals: list[dict[str, Any]] = []
    checks = [
        ("asset_movement", TOKEN_TRANSFER_RE.search(body) or ETH_TRANSFER_RE.search(body)),
        ("external_call", LOW_LEVEL_RE.search(body) or EXTERNAL_CALL_RE.search(body)),
        ("oracle_read", ORACLE_RE.search(body)),
        ("signature_path", SIGNATURE_RE.search(body + " " + name)),
        ("proof_path", PROOF_RE.search(body + " " + name)),
        ("initializer_or_upgrade", INIT_RE.search(body + " " + name)),
        ("loop", LOOP_RE.search(body)),
        ("accounting_variable", ACCOUNTING_RE.search(body + " " + name)),
        ("role_check", ROLE_RE.search(body) or any(re.search(r"owner|role|admin|keeper|manager", m, re.I) for m in fn.get("modifiers", []))),
    ]
    for kind, hit in checks:
        if hit:
            signals.append({"kind": kind, "file": file_path, "contract": contract["name"], "function": name, "line": fn.get("start_line"), "description": f"{kind} signal in {contract['name']}.{name}"})
    return signals


def index_real_repo(project_root: Path, *, repo_id: str | None = None, include_tests: bool = False) -> dict[str, Any]:
    idx = index_project(project_root, include_tests=include_tests)
    contracts: list[dict[str, Any]] = []
    interfaces: list[dict[str, Any]] = []
    libraries: list[dict[str, Any]] = []
    functions: list[dict[str, Any]] = []
    modifiers: list[dict[str, Any]] = []
    inheritance_edges: list[dict[str, Any]] = []
    state_variables: list[dict[str, Any]] = []
    structs: list[dict[str, Any]] = []
    mappings: list[dict[str, Any]] = []
    enums: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    imports: list[dict[str, Any]] = []
    external_calls: list[dict[str, Any]] = []
    token_transfers: list[dict[str, Any]] = []
    eth_transfers: list[dict[str, Any]] = []
    oracle_reads: list[dict[str, Any]] = []
    signature_paths: list[dict[str, Any]] = []
    proof_paths: list[dict[str, Any]] = []
    loops: list[dict[str, Any]] = []
    upgrade_patterns: list[dict[str, Any]] = []
    risk_signals: list[dict[str, Any]] = []
    prompt_injection_hits: list[dict[str, Any]] = []
    warnings: list[str] = []

    for file_row in idx.get("files", []):
        if file_row.get("kind") != "solidity":
            continue
        file_path = file_row["path"]
        text = file_row.get("text", "")
        imports.extend(extract_imports(file_path, text))
        scan = scan_text(text, source=file_path)
        prompt_injection_hits.extend({**hit, "treatment": "logged_as_untrusted_data"} for hit in scan.get("hits", []))
        for contract in file_row.get("contracts", []):
            cmeta = {"file": file_path, "name": contract["name"], "kind": contract["kind"], "inherits": contract.get("inherits", []), "start_line": contract.get("start_line"), "end_line": contract.get("end_line")}
            if contract["kind"] == "interface":
                interfaces.append(cmeta)
            elif contract["kind"] == "library":
                libraries.append(cmeta)
            else:
                contracts.append(cmeta)
            for parent in contract.get("inherits", []):
                inheritance_edges.append({"file": file_path, "child": contract["name"], "parent": parent})
            for mod in MODIFIER_RE.finditer(contract.get("body", "")):
                modifiers.append({"file": file_path, "contract": contract["name"], "name": mod.group(1), "line": contract.get("start_line", 1) + contract.get("body", "").count("\n", 0, mod.start())})
            states, srows, erows, evrows, errrows = extract_state(file_path, contract)
            state_variables.extend(states)
            mappings.extend([row for row in states if row.get("is_mapping")])
            structs.extend(srows)
            enums.extend(erows)
            events.extend(evrows)
            errors.extend(errrows)
            for fn in contract.get("functions", []):
                frow = fn_row(file_path, contract, fn)
                functions.append(frow)
                external_calls.extend(extract_occurrences(file_path, contract, fn, LOW_LEVEL_RE, "low_level_call"))
                external_calls.extend(extract_occurrences(file_path, contract, fn, EXTERNAL_CALL_RE, "external_contract_call"))
                token_transfers.extend(extract_occurrences(file_path, contract, fn, TOKEN_TRANSFER_RE, "token_transfer"))
                eth_transfers.extend(extract_occurrences(file_path, contract, fn, ETH_TRANSFER_RE, "eth_transfer"))
                oracle_reads.extend(extract_occurrences(file_path, contract, fn, ORACLE_RE, "oracle_read"))
                signature_paths.extend(extract_occurrences(file_path, contract, fn, SIGNATURE_RE, "signature_path"))
                proof_paths.extend(extract_occurrences(file_path, contract, fn, PROOF_RE, "proof_path"))
                loops.extend(extract_occurrences(file_path, contract, fn, LOOP_RE, "loop"))
                upgrade_patterns.extend(upgrade_occurrences(file_path, contract, fn))
                risk_signals.extend(risk_signals_for_function(file_path, contract, fn))

    if idx.get("read_files") and not (contracts or interfaces or libraries):
        warnings.append("Solidity files were read but no contracts/interfaces/libraries were parsed")
    return {
        "repo_id": repo_id or repo_id_for(project_root),
        "project_root": str(project_root),
        "files_indexed": idx.get("read_files", []),
        "imports": imports,
        "contracts": contracts,
        "interfaces": interfaces,
        "libraries": libraries,
        "functions": functions,
        "modifiers": modifiers,
        "inheritance_edges": inheritance_edges,
        "state_variables": state_variables,
        "structs": structs,
        "mappings": mappings,
        "enums": enums,
        "events": events,
        "errors": errors,
        "external_calls": external_calls,
        "token_transfers": token_transfers,
        "eth_transfers": eth_transfers,
        "oracle_reads": oracle_reads,
        "signature_paths": signature_paths,
        "proof_paths": proof_paths,
        "loops": loops,
        "upgrade_patterns": upgrade_patterns,
        "external_dependencies": imports,
        "prompt_injection_hits": prompt_injection_hits,
        "risk_signals": risk_signals,
        "indexing_warnings": warnings,
        "answer_key_access": any("expected_findings" in p or "expected_results" in p for p in idx.get("read_files", [])),
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
    }


def self_test() -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "src").mkdir()
        (root / "src" / "System.sol").write_text('pragma solidity ^0.8.20; interface IOracle{function price() external view returns(uint);} library L{function x(uint a) internal pure returns(uint){return a;}} contract Base{modifier onlyOwner(){_;}} contract Vault is Base { mapping(address=>uint) public bal; event Deposit(address indexed user,uint amount); function initialize() external {} function deposit(address token,uint amount) external { IERC20(token).transferFrom(msg.sender,address(this),amount); bal[msg.sender]+=amount; } function claim(bytes calldata sig) external onlyOwner { for(uint i; i<1; ++i){ ecrecover(bytes32(0),0,bytes32(0),bytes32(0)); } } } interface IERC20{function transferFrom(address,address,uint) external returns(bool);}')
        result = index_real_repo(root, repo_id="self")
        ok = result["contracts"] and result["interfaces"] and result["libraries"] and result["functions"] and result["token_transfers"] and result["signature_paths"] and result["upgrade_patterns"]
        return {"status": "PASS" if ok else "FAIL", "index": result}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Index a real Solidity/EVM repository for bounty triage")
    p.add_argument("project_root", nargs="?")
    p.add_argument("--repo-id", default="")
    p.add_argument("--include-tests", action="store_true")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        result = self_test()
    else:
        if not args.project_root:
            raise SystemExit("project_root required unless --self-test")
        result = index_real_repo(Path(args.project_root), repo_id=args.repo_id or None, include_tests=args.include_tests)
    print(json.dumps(result, indent=2))
    return 0 if result.get("status", "PASS") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
