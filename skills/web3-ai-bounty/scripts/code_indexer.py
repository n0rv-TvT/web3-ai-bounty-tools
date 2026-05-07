#!/usr/bin/env python3
"""Heuristic Solidity code indexer for Web3 audit x-ray work.

Produces a deterministic JSON artifact containing contract surfaces, storage
declarations, function facts, and a best-effort call graph. This is a lead
generator, not a vulnerability scanner. It intentionally uses only Python's
standard library so it can run in sparse bounty environments.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "1.0.0"
EXCLUDE_DIRS = {".git", "node_modules", "lib", "out", "cache", "artifacts", "broadcast", "coverage", ".venv", "venv"}
TEST_HINTS = {"test", "tests", "mock", "mocks", "script", "scripts"}
VISIBILITY = {"public", "private", "internal", "external"}
MUTABILITY = {"view", "pure", "payable"}
VAR_QUALIFIERS = {"public", "private", "internal", "external", "constant", "immutable", "transient", "override"}
CONTROL_WORDS = {
    "if", "for", "while", "do", "return", "require", "assert", "revert", "emit", "new", "delete",
    "unchecked", "assembly", "try", "catch", "else", "super", "this", "type", "abi",
}
BUILTIN_CALLS = CONTROL_WORDS | {"keccak256", "ecrecover", "sha256", "ripemd160", "blockhash", "addmod", "mulmod"}
SENSITIVE_STORAGE_TERMS = {
    "balance", "balances", "asset", "assets", "share", "shares", "supply", "debt", "reserve", "reserves",
    "liquidity", "collateral", "price", "oracle", "index", "reward", "rewards", "nonce", "nonces",
    "owner", "admin", "role", "roles", "signer", "signers", "guardian", "keeper", "implementation",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git_value(root: Path, args: list[str]) -> str | None:
    try:
        return subprocess.check_output(["git", *args], cwd=root, text=True, stderr=subprocess.DEVNULL).strip() or None
    except Exception:
        return None


def strip_comments(src: str) -> str:
    """Strip Solidity comments while preserving line numbers."""
    src = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), src, flags=re.S)
    return re.sub(r"//.*", "", src)


def compact(s: str) -> str:
    return " ".join(s.split())


def line_no(src: str, idx: int) -> int:
    return src.count("\n", 0, max(idx, 0)) + 1


def find_matching(src: str, start: int, open_ch: str = "{", close_ch: str = "}") -> int:
    depth = 0
    quote: str | None = None
    escape = False
    i = start
    while i < len(src):
        ch = src[i]
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
        else:
            if ch in {'"', "'"}:
                quote = ch
            elif ch == open_ch:
                depth += 1
            elif ch == close_ch:
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return -1


def find_signature_end(src: str, start: int) -> tuple[int, str]:
    """Return index of top-level `{`/`;` and delimiter."""
    paren = bracket = 0
    quote: str | None = None
    escape = False
    i = start
    while i < len(src):
        ch = src[i]
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
        else:
            if ch in {'"', "'"}:
                quote = ch
            elif ch == "(":
                paren += 1
            elif ch == ")":
                paren = max(paren - 1, 0)
            elif ch == "[":
                bracket += 1
            elif ch == "]":
                bracket = max(bracket - 1, 0)
            elif paren == 0 and bracket == 0 and ch in "{;":
                return i, ch
        i += 1
    return len(src), ""


def iter_sol_files(root: Path, src_dir: str | None, include_tests: bool) -> Iterable[Path]:
    bases: list[Path]
    if src_dir:
        candidate = root / src_dir
        bases = [candidate] if candidate.exists() else [root]
    else:
        discovered = [root / name for name in ("src", "contracts") if (root / name).exists()]
        bases = discovered or [root]
    seen: set[Path] = set()
    for base in bases:
        for path in base.rglob("*.sol"):
            if path in seen:
                continue
            seen.add(path)
            parts = {p.lower() for p in path.parts}
            if parts & EXCLUDE_DIRS:
                continue
            if not include_tests:
                lowered = str(path).lower()
                if lowered.endswith(".t.sol") or any(part in TEST_HINTS for part in parts):
                    continue
                if "test" in path.name.lower() or "mock" in path.name.lower():
                    continue
            yield path


def parse_imports(src: str) -> list[dict[str, Any]]:
    imports = []
    for m in re.finditer(r"\bimport\s+(?:[^;]*?\s+from\s+)?[\"']([^\"']+)[\"']\s*;", src, flags=re.S):
        imports.append({"path": m.group(1), "line": line_no(src, m.start()), "statement": compact(m.group(0))})
    return imports


def split_base_contracts(base_text: str | None) -> list[str]:
    if not base_text:
        return []
    out = []
    for part in base_text.split(","):
        name = compact(part).split("(")[0].strip()
        if name:
            out.append(name)
    return out


def iter_top_level_statements(body: str) -> Iterable[tuple[int, int, str]]:
    paren = brace = bracket = 0
    quote: str | None = None
    escape = False
    start = 0
    for i, ch in enumerate(body):
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in {'"', "'"}:
            quote = ch
        elif ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(paren - 1, 0)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(bracket - 1, 0)
        elif ch == "{":
            brace += 1
        elif ch == "}":
            brace = max(brace - 1, 0)
        elif ch == ";" and paren == 0 and brace == 0 and bracket == 0:
            stmt = body[start : i + 1]
            yield start, i + 1, stmt
            start = i + 1


def statement_prefix(stmt: str) -> str:
    s = compact(stmt).lstrip()
    return s.split(" ", 1)[0] if s else ""


def split_state_initializer(clean_stmt: str) -> tuple[str, str]:
    """Split a state declaration on assignment without breaking mapping `=>`."""
    paren = bracket = 0
    quote: str | None = None
    escape = False
    for i, ch in enumerate(clean_stmt):
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in {'"', "'"}:
            quote = ch
        elif ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(paren - 1, 0)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(bracket - 1, 0)
        elif ch == "=" and paren == 0 and bracket == 0:
            prev_ch = clean_stmt[i - 1] if i > 0 else ""
            next_ch = clean_stmt[i + 1] if i + 1 < len(clean_stmt) else ""
            if prev_ch in {"=", "!", "<", ">"} or next_ch in {"=", ">"}:
                continue
            return clean_stmt[:i].strip(), clean_stmt[i + 1 :].strip()
    return clean_stmt.strip(), ""


def parse_state_decl(stmt: str, abs_start: int, file_src: str, slot_hint: int) -> dict[str, Any] | None:
    clean = compact(stmt).rstrip(";")
    if not clean:
        return None
    first = statement_prefix(clean)
    if first in {"using", "event", "error", "function", "modifier", "constructor", "fallback", "receive", "struct", "enum", "type"}:
        return None
    before_eq, initializer = split_state_initializer(clean)
    ids = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", before_eq)
    if not ids:
        return None
    name = ids[-1]
    if name in VAR_QUALIFIERS or name in CONTROL_WORDS:
        return None
    type_part = before_eq[: before_eq.rfind(name)].strip()
    if not type_part:
        return None
    visibility = next((v for v in VISIBILITY if re.search(rf"\b{v}\b", type_part)), "internal")
    qualifiers = [q for q in VAR_QUALIFIERS if re.search(rf"\b{q}\b", type_part)]
    var_type = compact(re.sub(r"\b(" + "|".join(sorted(VAR_QUALIFIERS)) + r")\b", " ", type_part)).strip()
    storage_persistent = "constant" not in qualifiers and "immutable" not in qualifiers
    lower = name.lower() + " " + var_type.lower()
    tags = sorted({term for term in SENSITIVE_STORAGE_TERMS if term in lower})
    return {
        "name": name,
        "type": var_type,
        "visibility": visibility,
        "qualifiers": sorted(qualifiers),
        "line": line_no(file_src, abs_start + max(stmt.find(before_eq), 0)),
        "slot_order_hint": slot_hint if storage_persistent else None,
        "storage_persistent": storage_persistent,
        "initializer": initializer[:240],
        "sensitive_tags": tags,
    }


def parse_params(text: str) -> list[dict[str, str]]:
    params = []
    text = compact(text)
    if not text:
        return params
    depth = 0
    current = []
    chunks = []
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(depth - 1, 0)
        if ch == "," and depth == 0:
            chunks.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        chunks.append("".join(current).strip())
    for chunk in chunks:
        ids = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", chunk)
        name = ""
        if ids and ids[-1] not in {"memory", "storage", "calldata", "payable"}:
            name = ids[-1]
            typ = chunk[: chunk.rfind(name)].strip()
        else:
            typ = chunk
        params.append({"name": name, "type": compact(typ)})
    return params


def parse_returns(tail: str) -> list[dict[str, str]]:
    m = re.search(r"\breturns\s*\(", tail)
    if not m:
        return []
    open_idx = tail.find("(", m.start())
    close_idx = find_matching(tail, open_idx, "(", ")")
    if close_idx == -1:
        return []
    return parse_params(tail[open_idx + 1 : close_idx])


def parse_function_modifiers(tail: str) -> list[str]:
    cleaned = re.sub(r"\breturns\s*\([^)]*\)", " ", tail, flags=re.S)
    cleaned = re.sub(r"\b(external|public|internal|private|view|pure|payable|virtual|override)\b(?:\s*\([^)]*\))?", " ", cleaned)
    mods = []
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\b(?:\s*\([^;{}]*\))?", cleaned):
        name = m.group(1)
        if name not in {"returns"} and name not in mods:
            mods.append(name)
    return mods


def function_kind_and_name(token: str) -> tuple[str, str]:
    token = compact(token)
    if token.startswith("function"):
        return "function", token.split()[1]
    if token.startswith("constructor"):
        return "constructor", "constructor"
    if token.startswith("fallback"):
        return "fallback", "fallback"
    if token.startswith("receive"):
        return "receive", "receive"
    return "function", "<unknown>"


def extract_auth_checks(body: str) -> list[str]:
    checks = []
    patterns = [
        r"require\s*\([^;]*(?:msg\.sender|hasRole|_checkRole|owner\s*\(|onlyOwner|isOwner)[^;]*;",
        r"if\s*\([^)]*(?:msg\.sender|hasRole|_checkRole|owner\s*\()[^)]*\)\s*(?:revert|throw|\{\s*revert)[^;]*;",
    ]
    for pat in patterns:
        for m in re.finditer(pat, body, flags=re.S):
            checks.append(compact(m.group(0))[:260])
    return checks[:20]


def extract_reverts(body: str) -> list[str]:
    out = []
    for m in re.finditer(r"\b(?:require|assert|revert)\s*\([^;]*;", body, flags=re.S):
        out.append(compact(m.group(0))[:220])
    return out[:30]


def extract_emits(body: str) -> list[str]:
    return sorted(set(re.findall(r"\bemit\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", body)))[:30]


def extract_creates(body: str) -> list[str]:
    return sorted(set(re.findall(r"\bnew\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\{|\()", body)))[:30]


def extract_external_calls(body: str) -> list[dict[str, Any]]:
    calls: dict[tuple[str, str], dict[str, Any]] = {}
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\{|\()", body):
        target, fn = m.group(1), m.group(2)
        if target in {"super", "this", "vm", "console", "console2", "abi", "Math", "SafeCast"}:
            continue
        key = (target, fn)
        calls.setdefault(key, {"target": target, "function": fn, "line_offset": body.count("\n", 0, m.start()) + 1, "call": f"{target}.{fn}"})
    return list(calls.values())[:80]


def extract_low_level_calls(body: str) -> list[dict[str, Any]]:
    out = []
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?)\s*\.\s*(call|delegatecall|staticcall|send)\s*(?:\{|\()", body):
        out.append({"target": compact(m.group(1)), "kind": m.group(2), "line_offset": body.count("\n", 0, m.start()) + 1})
    return out[:50]


def extract_internal_calls(body: str, function_names: set[str], self_name: str) -> list[str]:
    calls = set()
    for m in re.finditer(r"(?<!\.)\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", body):
        name = m.group(1)
        if name in BUILTIN_CALLS or name == self_name:
            continue
        if name in function_names:
            calls.add(name)
    return sorted(calls)


def extract_reads_writes(body: str, state_names: set[str]) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    writes: set[str] = set()
    reads: set[str] = set()
    write_events: list[dict[str, Any]] = []
    for name in state_names:
        if re.search(rf"\b{re.escape(name)}\b", body):
            reads.add(name)
    assign_pat = r"\b([A-Za-z_][A-Za-z0-9_]*)(?:\s*\[[^\]]+\])?\s*(\+\+|--|\+=|-=|\*=|/=|%=|=)"
    for m in re.finditer(assign_pat, body):
        var = m.group(1)
        if var in state_names:
            writes.add(var)
            write_events.append({"variable": var, "op": m.group(2), "line_offset": body.count("\n", 0, m.start()) + 1, "snippet": compact(body[m.start() : body.find(";", m.start()) + 1])[:220]})
    for m in re.finditer(r"\bdelete\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*\[[^\]]+\])?", body):
        var = m.group(1)
        if var in state_names:
            writes.add(var)
            write_events.append({"variable": var, "op": "delete", "line_offset": body.count("\n", 0, m.start()) + 1, "snippet": compact(body[m.start() : body.find(";", m.start()) + 1])[:220]})
    return sorted(reads), sorted(writes), write_events[:80]


def classify_asset_flow(body: str, payable: bool) -> dict[str, Any]:
    incoming = []
    outgoing = []
    if payable or "msg.value" in body:
        incoming.append("native-value")
    if re.search(r"\.\s*(safeTransferFrom|transferFrom)\s*\([^;]*(msg\.sender|_msgSender\s*\(\))", body, flags=re.S):
        incoming.append("token-transfer-from-caller")
    if re.search(r"\.\s*(safeTransfer|transfer)\s*\(", body):
        outgoing.append("token-transfer-out")
    if re.search(r"\.\s*call\s*\{\s*value\s*:", body):
        outgoing.append("native-call-value-out")
    return {"incoming": sorted(set(incoming)), "outgoing": sorted(set(outgoing)), "value_moving": bool(incoming or outgoing)}


def risk_tags_for_function(fn: dict[str, Any], body: str) -> list[str]:
    tags: set[str] = set()
    name = fn["name"].lower()
    mods = {m.lower() for m in fn.get("modifiers", [])}
    vis = fn.get("visibility", "")
    if vis in {"external", "public"} and fn.get("asset_flow", {}).get("outgoing") and not fn.get("auth_checks") and not any(m.startswith("only") or "role" in m for m in mods):
        tags.add("permissionless-value-out")
    if fn.get("low_level_calls"):
        tags.add("low-level-call")
    if any(c.get("kind") == "delegatecall" for c in fn.get("low_level_calls", [])):
        tags.add("delegatecall")
    if name in {"initialize", "init"} and vis in {"external", "public"} and not any("initializer" in m for m in mods):
        tags.add("initializer-without-initializer-modifier")
    if re.search(r"\bconfirmAt\s*\[\s*[^\]]+\s*\]\s*=\s*(?:uint256\()?1\)?\s*;", body) and not re.search(r"bytes32\s*\(\s*0\s*\)|LEGACY_STATUS_NONE", body):
        tags.add("zero-root-preapproval-signal")
    if name == "acceptableroot" and "confirmAt" in body and "LEGACY_STATUS_PROCESSED" in body and "LEGACY_STATUS_NONE" not in body:
        tags.add("zero-root-acceptable-signal")
    if re.search(r"acceptableRoot\s*\(\s*messages\s*\[", body) and "keccak" in body:
        tags.add("message-default-root-gate")
    if "ecrecover" in body or "ECDSA" in body or ".recover(" in body:
        tags.add("signature-boundary")
        if not re.search(r"\b(nonce|nonces|deadline|expires|expiry|domainSeparator|DOMAIN_SEPARATOR|chainid|chainId)\b", body):
            tags.add("signature-replay-signal")
    if "latestRoundData" in body:
        tags.add("chainlink-oracle")
        missing = [term for term in ("updatedAt", "answeredInRound") if term not in body]
        if missing:
            tags.add("oracle-freshness-signal")
    if "getPriceUnsafe" in body or "slot0" in body:
        tags.add("spot-or-unsafe-oracle-signal")
    if re.search(r"\.\s*(call|safeTransfer|transfer)\s*(?:\{|\()", body) and fn.get("writes"):
        first_call = re.search(r"\.\s*(call|safeTransfer|transfer)\s*(?:\{|\()", body)
        first_write = None
        for event in fn.get("write_events", []):
            line = event.get("line_offset", 0)
            if first_write is None or line < first_write:
                first_write = line
        if first_call and first_write is not None and (body.count("\n", 0, first_call.start()) + 1) < first_write:
            tags.add("external-call-before-state-write")
    if name.startswith("upgrade") or "upgradeTo" in body:
        tags.add("upgrade-boundary")
    if fn.get("state_mutability") == "payable":
        tags.add("payable-entrypoint")
    return sorted(tags)


def parse_modifiers(body: str, contract_offset: int, file_src: str) -> list[dict[str, Any]]:
    mods = []
    for m in re.finditer(r"\bmodifier\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\((.*?)\))?", body, flags=re.S):
        sig_end, delim = find_signature_end(body, m.end())
        if delim != "{":
            continue
        end = find_matching(body, sig_end, "{", "}")
        if end == -1:
            continue
        mod_body = body[sig_end + 1 : end]
        mods.append({
            "name": m.group(1),
            "line_start": line_no(file_src, contract_offset + m.start()),
            "line_end": line_no(file_src, contract_offset + end),
            "parameters": parse_params(m.group(2) or ""),
            "auth_checks": extract_auth_checks(mod_body),
            "reverts": extract_reverts(mod_body),
            "uses_placeholder": "_;" in mod_body,
        })
    return mods


def parse_functions(body: str, contract_offset: int, file_src: str, state_names: set[str]) -> list[dict[str, Any]]:
    function_spans: list[tuple[int, int, dict[str, Any], str]] = []
    pattern = r"\b(function\s+[A-Za-z_][A-Za-z0-9_]*|constructor|fallback|receive)\s*\("
    for m in re.finditer(pattern, body):
        open_idx = body.find("(", m.start())
        close_idx = find_matching(body, open_idx, "(", ")")
        if close_idx == -1:
            continue
        sig_end, delim = find_signature_end(body, close_idx + 1)
        signature = body[m.start() : sig_end]
        tail = body[close_idx + 1 : sig_end]
        kind, name = function_kind_and_name(m.group(1))
        visibility = next((v for v in VISIBILITY if re.search(rf"\b{v}\b", signature)), "public" if kind in {"constructor", "receive", "fallback"} else "internal")
        state_mutability = next((v for v in MUTABILITY if re.search(rf"\b{v}\b", signature)), "nonpayable")
        fn_body = ""
        end = sig_end
        has_body = delim == "{"
        if has_body:
            end = find_matching(body, sig_end, "{", "}")
            if end == -1:
                continue
            fn_body = body[sig_end + 1 : end]
        params = body[open_idx + 1 : close_idx]
        reads, writes, write_events = extract_reads_writes(fn_body, state_names)
        low_level = extract_low_level_calls(fn_body)
        fn = {
            "id": "",
            "name": name,
            "kind": kind,
            "line_start": line_no(file_src, contract_offset + m.start()),
            "line_end": line_no(file_src, contract_offset + end),
            "visibility": visibility,
            "state_mutability": state_mutability,
            "modifiers": parse_function_modifiers(tail),
            "parameters": parse_params(params),
            "returns": parse_returns(tail),
            "has_body": has_body,
            "reads": reads,
            "writes": writes,
            "write_events": write_events,
            "external_calls": extract_external_calls(fn_body),
            "low_level_calls": low_level,
            "internal_calls": [],
            "asset_flow": classify_asset_flow(fn_body, state_mutability == "payable"),
            "auth_checks": extract_auth_checks(fn_body),
            "emits": extract_emits(fn_body),
            "reverts": extract_reverts(fn_body),
            "creates": extract_creates(fn_body),
            "risk_tags": [],
            "signature": compact(signature),
        }
        function_spans.append((m.start(), end, fn, fn_body))
    names = {fn["name"] for _, _, fn, _ in function_spans}
    functions = []
    for _, _, fn, fn_body in function_spans:
        fn["internal_calls"] = extract_internal_calls(fn_body, names, fn["name"])
        fn["risk_tags"] = risk_tags_for_function(fn, fn_body)
        functions.append(fn)
    return functions


def parse_contracts(path: Path, root: Path, src: str, stripped: str, imports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    contracts = []
    header_re = re.compile(r"\b(?P<kind>abstract\s+contract|contract|interface|library)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:is\s+(?P<bases>[^{};]+?))?\s*\{", re.S)
    for m in header_re.finditer(stripped):
        open_idx = stripped.find("{", m.start())
        close_idx = find_matching(stripped, open_idx, "{", "}")
        if close_idx == -1:
            continue
        kind_raw = compact(m.group("kind"))
        abstract = kind_raw.startswith("abstract")
        kind = "contract" if "contract" in kind_raw else kind_raw
        body_start = open_idx + 1
        body = stripped[body_start:close_idx]
        slot = 0
        state_vars = []
        for stmt_start, _, stmt in iter_top_level_statements(body):
            decl = parse_state_decl(stmt, body_start + stmt_start, stripped, slot)
            if not decl:
                continue
            if decl["storage_persistent"]:
                slot += 1
            state_vars.append(decl)
        state_names = {v["name"] for v in state_vars}
        modifiers = parse_modifiers(body, body_start, stripped)
        functions = parse_functions(body, body_start, stripped, state_names)
        rel = str(path.relative_to(root))
        contract = {
            "id": f"{rel}:{m.group('name')}",
            "file": rel,
            "name": m.group("name"),
            "kind": kind,
            "abstract": abstract,
            "line_start": line_no(stripped, m.start()),
            "line_end": line_no(stripped, close_idx),
            "bases": split_base_contracts(m.group("bases")),
            "imports": [imp["path"] for imp in imports],
            "state_variables": state_vars,
            "modifiers": modifiers,
            "functions": functions,
            "events": sorted(set(re.findall(r"\bevent\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", body)))[:100],
            "errors": sorted(set(re.findall(r"\berror\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", body)))[:100],
        }
        for fn in contract["functions"]:
            fn["id"] = f"{contract['id']}.{fn['name']}@{fn['line_start']}"
        contracts.append(contract)
    return contracts


def build_callgraph(contracts: list[dict[str, Any]]) -> dict[str, Any]:
    internal_edges = []
    external_edges = []
    function_ids_by_contract: dict[str, dict[str, str]] = {}
    for c in contracts:
        function_ids_by_contract[c["id"]] = {f["name"]: f["id"] for f in c.get("functions", [])}
    for c in contracts:
        lookup = function_ids_by_contract[c["id"]]
        for f in c.get("functions", []):
            for target in f.get("internal_calls", []):
                internal_edges.append({"from": f["id"], "to": lookup.get(target, target), "kind": "internal", "function": target})
            for call in f.get("external_calls", []):
                external_edges.append({"from": f["id"], "target": call["target"], "function": call["function"], "kind": "external", "call": call["call"]})
            for call in f.get("low_level_calls", []):
                external_edges.append({"from": f["id"], "target": call["target"], "function": call["kind"], "kind": "low-level", "call": f"{call['target']}.{call['kind']}"})
    return {"internal_edges": internal_edges, "external_edges": external_edges}


def build_storage_index(contracts: list[dict[str, Any]]) -> dict[str, Any]:
    variables = []
    writers: dict[str, list[str]] = {}
    readers: dict[str, list[str]] = {}
    for c in contracts:
        for v in c.get("state_variables", []):
            key = f"{c['name']}.{v['name']}"
            variables.append({"key": key, "contract": c["name"], **v})
            writers[key] = []
            readers[key] = []
        state_names = {v["name"] for v in c.get("state_variables", [])}
        for f in c.get("functions", []):
            for w in f.get("writes", []):
                if w in state_names:
                    writers.setdefault(f"{c['name']}.{w}", []).append(f["id"])
            for r in f.get("reads", []):
                if r in state_names:
                    readers.setdefault(f"{c['name']}.{r}", []).append(f["id"])
    multi_writers = {k: v for k, v in writers.items() if len(v) >= 2}
    sensitive = [v for v in variables if v.get("sensitive_tags")]
    return {"variables": variables, "writers": writers, "readers": readers, "variables_with_multiple_writers": multi_writers, "sensitive_variables": sensitive}


def build_risk_signals(contracts: list[dict[str, Any]], storage_index: dict[str, Any]) -> list[dict[str, Any]]:
    signals = []
    for c in contracts:
        for f in c.get("functions", []):
            for tag in f.get("risk_tags", []):
                severity = "medium" if tag in {"permissionless-value-out", "delegatecall", "signature-replay-signal", "initializer-without-initializer-modifier", "zero-root-preapproval-signal", "zero-root-acceptable-signal", "message-default-root-gate"} else "info"
                signals.append({
                    "type": tag,
                    "severity": severity,
                    "file": c["file"],
                    "line": f["line_start"],
                    "contract": c["name"],
                    "function": f["name"],
                    "message": f"{c['name']}.{f['name']} has {tag.replace('-', ' ')} signal",
                    "lead_template": f"Because a normal caller may reach {c['name']}.{f['name']} while {tag.replace('-', ' ')} exists, test whether an invariant can be broken and prove concrete impact.",
                })
    for key, writers in storage_index.get("variables_with_multiple_writers", {}).items():
        var = key.split(".", 1)[1] if "." in key else key
        if any(term in var.lower() for term in SENSITIVE_STORAGE_TERMS):
            signals.append({
                "type": "sensitive-storage-multiple-writers",
                "severity": "info",
                "file": "",
                "line": 0,
                "contract": key.split(".", 1)[0],
                "function": "",
                "message": f"{key} has {len(writers)} writer functions; compare sibling guards and accounting paths",
                "lead_template": f"Because {key} is written by multiple paths, compare guards/order/accounting to find a path that desynchronizes state.",
            })
    return signals


def build_index(root: Path, src_dir: str | None, include_tests: bool) -> dict[str, Any]:
    source_files = []
    contracts = []
    files = sorted(iter_sol_files(root, src_dir, include_tests), key=lambda p: str(p.relative_to(root)))
    for path in files:
        raw = path.read_text(errors="replace")
        stripped = strip_comments(raw)
        imports = parse_imports(stripped)
        source_files.append({
            "path": str(path.relative_to(root)),
            "sha256": sha256_file(path),
            "lines": raw.count("\n") + 1,
            "imports": imports,
        })
        contracts.extend(parse_contracts(path, root, raw, stripped, imports))
    storage_index = build_storage_index(contracts)
    callgraph = build_callgraph(contracts)
    risk_signals = build_risk_signals(contracts, storage_index)
    public_functions = [f for c in contracts for f in c.get("functions", []) if f.get("visibility") in {"public", "external"}]
    value_moving = [f for f in public_functions if f.get("asset_flow", {}).get("value_moving")]
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "project": {
            "root": str(root),
            "branch": git_value(root, ["rev-parse", "--abbrev-ref", "HEAD"]),
            "commit": git_value(root, ["rev-parse", "HEAD"]),
        },
        "source_files": source_files,
        "contracts": contracts,
        "storage_index": storage_index,
        "callgraph": callgraph,
        "risk_signals": risk_signals,
        "metrics": {
            "source_file_count": len(source_files),
            "contract_count": len(contracts),
            "state_variable_count": sum(len(c.get("state_variables", [])) for c in contracts),
            "function_count": sum(len(c.get("functions", [])) for c in contracts),
            "public_external_function_count": len(public_functions),
            "value_moving_public_function_count": len(value_moving),
            "risk_signal_count": len(risk_signals),
        },
    }


def print_markdown(index: dict[str, Any], risk_limit: int) -> None:
    metrics = index["metrics"]
    print("# Solidity Code Index")
    print()
    print(f"Generated: {index['generated_at']}")
    print(f"Contracts: {metrics['contract_count']} | Functions: {metrics['function_count']} | State vars: {metrics['state_variable_count']}")
    print(f"Public/external functions: {metrics['public_external_function_count']} | Value-moving public functions: {metrics['value_moving_public_function_count']}")
    print()
    print("## Contracts")
    for c in index.get("contracts", []):
        print(f"- `{c['name']}` ({c['kind']}) `{c['file']}:{c['line_start']}` bases={', '.join(c.get('bases', [])) or '-'}")
        public = [f for f in c.get("functions", []) if f.get("visibility") in {"public", "external"}]
        value = [f for f in public if f.get("asset_flow", {}).get("value_moving")]
        print(f"  - state vars: {len(c.get('state_variables', []))}; public/external functions: {len(public)}; value-moving: {len(value)}")
    print()
    print("## Top Risk Signals (lead generators, not findings)")
    for sig in index.get("risk_signals", [])[:risk_limit]:
        loc = f"{sig.get('file') or '-'}:{sig.get('line') or '-'}"
        fn = f"{sig.get('contract')}.{sig.get('function')}" if sig.get("function") else sig.get("contract")
        print(f"- [{sig['severity']}] `{sig['type']}` at {loc} `{fn}` — {sig['message']}")
    print()
    print("Use these signals to create Lead DB entries, then manually prove or kill them.")


def main() -> int:
    ap = argparse.ArgumentParser(description="Build a Solidity AST/storage/callgraph index artifact")
    ap.add_argument("root", nargs="?", default=".", help="project root")
    ap.add_argument("--src-dir", help="optional source directory under root")
    ap.add_argument("--include-tests", action="store_true", help="include tests, mocks, and scripts")
    ap.add_argument("--out", help="write JSON index to this path")
    ap.add_argument("--json", action="store_true", help="print JSON to stdout instead of Markdown summary")
    ap.add_argument("--risk-limit", type=int, default=20)
    args = ap.parse_args()

    root = Path(args.root).resolve()
    index = build_index(root, args.src_dir, args.include_tests)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(index, indent=2) + "\n")
    if args.json:
        print(json.dumps(index, indent=2))
    else:
        print_markdown(index, args.risk_limit)
        if args.out:
            print()
            print(f"JSON written to: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
