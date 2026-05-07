#!/usr/bin/env python3
"""Normalize Web3 scanner output into bounty-grade lead candidates.

This is Component 3 of the local Web3 audit engine. It ingests noisy scanner
formats, maps findings into a canonical taxonomy, deduplicates, suppresses
known non-bounty noise, enriches with the code index when available, and emits
Lead DB-ready rows. Scanner output remains evidence level 1: it creates leads,
not findings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "1.0.0"

SEVERITY_ORDER = {"UNKNOWN": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
CONFIDENCE_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CONFIRMED": 4}

SEVERITY_ALIASES = {
    "optimization": "INFO",
    "informational": "INFO",
    "info": "INFO",
    "note": "INFO",
    "warning": "LOW",
    "low": "LOW",
    "medium": "MEDIUM",
    "moderate": "MEDIUM",
    "major": "HIGH",
    "high": "HIGH",
    "critical": "CRITICAL",
}

CONFIDENCE_ALIASES = {
    "unknown": "UNKNOWN",
    "none": "UNKNOWN",
    "low": "LOW",
    "medium": "MEDIUM",
    "moderate": "MEDIUM",
    "high": "HIGH",
    "certain": "CONFIRMED",
    "confirmed": "CONFIRMED",
    "symbolic": "MEDIUM",
}

IMPACT_TYPES = {
    "unknown", "stolen-funds", "frozen-funds", "bad-debt", "unauthorized-privileged-action",
    "account-takeover", "sensitive-data-exposure", "unsafe-signing-tool-execution", "governance-corruption", "other",
}

NOISE_RULES: list[tuple[list[str], str]] = [
    (["naming-convention", "naming convention", "mixedcase", "similar-names"], "style/naming issue without direct bounty impact"),
    (["solc-version", "compiler-version", "old solc", "pragma", "floating pragma"], "compiler pragma/version warning without exploit path"),
    (["constable-states", "immutable-states", "could be constant", "could be immutable"], "gas/best-practice state mutability suggestion"),
    (["external-function", "public function that could be external"], "gas/interface optimization"),
    (["unused", "dead-code", "dead code", "unreachable code"], "unused/dead code signal without reachability"),
    (["too-many-digits", "conformance", "license", "spdx", "documentation"], "style/documentation-only signal"),
    (["cache-array-length", "costly-loop", "gas-", "gas optimization"], "gas optimization, not security impact"),
]

BUG_CLASS_RULES: list[dict[str, Any]] = [
    {
        "patterns": ["reentrancy", "external-call-before-state", "call before state", "callback"],
        "bug_class": "reentrancy-or-callback-ordering",
        "category": "execution-ordering",
        "impact_type": "stolen-funds",
        "tags": ["external-call", "state-ordering"],
        "impact_weight": 3,
        "poc_weight": 2,
        "proof": "Trace whether a normal attacker-controlled callback can reenter a sibling path or observe stale state, then assert attacker gain, victim loss, bad debt, or frozen funds.",
        "questions": [
            "Which state is updated after the external call?",
            "Can the callback reach another function touching the same state?",
            "What exact balance/accounting delta proves impact?",
        ],
    },
    {
        "patterns": ["arbitrary-send", "arbitrary send", "arbitrary-transfer", "arbitrary transfer", "unprotected transfer", "unrestricted transfer"],
        "bug_class": "arbitrary-asset-transfer",
        "category": "access-control",
        "impact_type": "stolen-funds",
        "tags": ["asset-transfer", "permissions"],
        "impact_weight": 3,
        "poc_weight": 3,
        "proof": "Show a normal attacker can choose source/recipient/amount or trigger unauthorized transfer, then assert attacker balance increases and victim/protocol balance decreases.",
        "questions": ["Who controls token/from/to/amount?", "Is approval or role actually required?", "Can the attacker receive funds in a PoC?"],
    },
    {
        "patterns": ["delegatecall", "controlled-delegatecall", "arbitrary delegatecall", "delegate call"],
        "bug_class": "controlled-delegatecall",
        "category": "delegatecall",
        "impact_type": "unauthorized-privileged-action",
        "tags": ["delegatecall", "code-execution"],
        "impact_weight": 3,
        "poc_weight": 2,
        "proof": "Prove a normal attacker controls the delegatecall target/calldata and can modify privileged storage, drain funds, or corrupt security state.",
        "questions": ["Can attacker choose target?", "What storage slot or asset changes?", "Is this path deployed and reachable?"],
    },
    {
        "patterns": ["unchecked-transfer", "unchecked transfer", "unchecked-lowlevel", "unchecked low", "unchecked-send", "unchecked call", "unchecked return"],
        "bug_class": "unchecked-call-or-token-return",
        "category": "external-call-return",
        "impact_type": "stolen-funds",
        "tags": ["unchecked-return", "token-transfer"],
        "impact_weight": 2,
        "poc_weight": 2,
        "proof": "Use a failing/no-return token or low-level call to show accounting advances without assets moving, then assert bad debt, stolen funds, or stuck funds.",
        "questions": ["Does state update despite failed transfer/call?", "Can attacker choose a non-standard token/callee?", "What invariant breaks?"],
    },
    {
        "patterns": ["access-control", "missing access", "unprotected", "onlyowner", "owner", "authorization", "auth", "role"],
        "bug_class": "access-control-mismatch",
        "category": "access-control",
        "impact_type": "unauthorized-privileged-action",
        "tags": ["permissions", "sibling-mismatch"],
        "impact_weight": 3,
        "poc_weight": 3,
        "proof": "Compare sibling/admin paths and prove a normal attacker performs a privileged state change, upgrade, parameter change, or fund movement.",
        "questions": ["Which sibling has the missing guard?", "Is the caller normal attacker or accepted role?", "What privileged action is achieved?"],
    },
    {
        "patterns": ["initialize", "initializer", "uninitialized", "reinitialize", "re-init", "reinit"],
        "bug_class": "proxy-or-initialization-bug",
        "category": "proxy-upgrade",
        "impact_type": "unauthorized-privileged-action",
        "tags": ["initializer", "proxy"],
        "impact_weight": 3,
        "poc_weight": 3,
        "proof": "Show the current proxy/implementation can be initialized or reinitialized by an attacker, then assert ownership/role takeover or fund sweep.",
        "questions": ["Is this proxy/implementation deployed and uninitialized?", "Can attacker call initializer now?", "What privileged state changes?"],
    },
    {
        "patterns": ["ecrecover", "ecdsa", "signature", "replay", "swc-117", "swc-121", "domain separator", "nonce"],
        "bug_class": "signature-replay-or-domain-bypass",
        "category": "signature-auth",
        "impact_type": "stolen-funds",
        "tags": ["signature", "replay"],
        "impact_weight": 3,
        "poc_weight": 3,
        "proof": "Replay the same signature or reuse it in the wrong chain/contract/action context, then assert unauthorized transfer or state change.",
        "questions": ["Where are nonce, deadline, chainId, verifyingContract, action, market, and recipient bound?", "Can the same signature be used twice?", "What asset/state moves?"],
    },
    {
        "patterns": ["oracle", "price", "latestrounddata", "pyth", "slot0", "twap", "stale", "answeredInRound", "updatedAt"],
        "bug_class": "oracle-price-manipulation-or-staleness",
        "category": "oracle",
        "impact_type": "bad-debt",
        "tags": ["oracle", "economic"],
        "impact_weight": 3,
        "poc_weight": 2,
        "proof": "Demonstrate stale/manipulated price changes collateral, shares, settlement, or liquidation enough to create profit, bad debt, or fund loss.",
        "questions": ["Can attacker influence or force stale price?", "What value-protected action consumes it?", "What profit/bad debt is asserted?"],
    },
    {
        "patterns": ["erc4626", "share", "shares", "rounding", "donation", "inflation", "empty vault", "first depositor", "totalassets"],
        "bug_class": "erc4626-or-share-accounting",
        "category": "accounting",
        "impact_type": "stolen-funds",
        "tags": ["shares", "accounting"],
        "impact_weight": 3,
        "poc_weight": 3,
        "proof": "Test empty vault, donation, rounding-to-zero, last-withdrawal, and preview/execution mismatch; assert attacker gain or victim loss.",
        "questions": ["Can direct donation or rounding affect shares?", "Is minShares enforced?", "Can attacker redeem victim value?"],
    },
    {
        "patterns": ["divide-before-multiply", "precision", "rounding", "loss of precision", "integer division", "overflow", "underflow", "swc-101"],
        "bug_class": "math-precision-or-overflow",
        "category": "math-accounting",
        "impact_type": "stolen-funds",
        "tags": ["math", "accounting"],
        "impact_weight": 2,
        "poc_weight": 2,
        "proof": "Find economically meaningful boundary inputs where math error creates profit, bad debt, unfair shares, or loss; assert exact delta.",
        "questions": ["Is the error more than dust?", "Can attacker choose inputs?", "Which invariant fails?"],
    },
    {
        "patterns": ["tx-origin", "tx.origin"],
        "bug_class": "tx-origin-authentication",
        "category": "authentication",
        "impact_type": "unauthorized-privileged-action",
        "tags": ["auth", "phishing-prereq"],
        "impact_weight": 1,
        "poc_weight": 2,
        "chain_required": True,
        "proof": "This usually requires a phishing/interaction chain; prove a normal victim action causes unauthorized fund/state movement and confirm it is in scope.",
        "questions": ["Does the program accept phishing-style chains?", "What normal victim action is required?", "What unauthorized action occurs?"],
    },
    {
        "patterns": ["timestamp", "block.timestamp", "block number", "weak-prng", "random", "entropy", "predictable"],
        "bug_class": "weak-randomness-or-time-dependence",
        "category": "mev-or-randomness",
        "impact_type": "other",
        "tags": ["randomness", "time"],
        "impact_weight": 1,
        "poc_weight": 1,
        "chain_required": True,
        "proof": "Prove miner/validator/user-controlled timing or predictable randomness creates deterministic accepted impact, not generic MEV/griefing.",
        "questions": ["Is MEV/timestamp manipulation in scope?", "Can attacker deterministically profit?", "Can a local PoC assert the impact?"],
    },
]

DEFAULT_CLASS = {
    "bug_class": "scanner-signal",
    "category": "unknown",
    "impact_type": "unknown",
    "tags": ["scanner"],
    "impact_weight": 1,
    "poc_weight": 1,
    "proof": "Manually confirm reachability from normal attacker privileges, identify concrete accepted impact, and write a PoC with assertions.",
    "questions": ["Is the line reachable?", "What asset/state changes?", "Can a minimal PoC prove it?"],
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def stable_hash(obj: Any, length: int = 16) -> str:
    raw = json.dumps(obj, sort_keys=True, default=str, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()[:length]


def compact(s: Any, limit: int | None = None) -> str:
    text = " ".join(str(s or "").split())
    if limit and len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def as_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except Exception:
        return None


def normalize_path(path: Any) -> str | None:
    if not path:
        return None
    text = str(path).replace("\\", "/")
    for marker in ("/src/", "/contracts/", "/test/", "/script/"):
        if marker in text:
            return text.split(marker, 1)[1] if marker in {"/src/", "/contracts/"} else marker.strip("/") + "/" + text.split(marker, 1)[1]
    return text.lstrip("./")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(errors="replace"))


def normalize_severity(value: Any) -> str:
    text = str(value or "").strip().lower().replace("_", "-")
    if text in SEVERITY_ALIASES:
        return SEVERITY_ALIASES[text]
    if text.startswith("high"):
        return "HIGH"
    if text.startswith("med"):
        return "MEDIUM"
    if text.startswith("crit"):
        return "CRITICAL"
    if text.startswith("low"):
        return "LOW"
    if text.startswith("info"):
        return "INFO"
    return "UNKNOWN"


def normalize_confidence(value: Any) -> str:
    text = str(value or "").strip().lower().replace("_", "-")
    if text in CONFIDENCE_ALIASES:
        return CONFIDENCE_ALIASES[text]
    if text.startswith("high"):
        return "HIGH"
    if text.startswith("med"):
        return "MEDIUM"
    if text.startswith("low"):
        return "LOW"
    return "UNKNOWN"


def max_severity(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b


def max_confidence(a: str, b: str) -> str:
    return a if CONFIDENCE_ORDER.get(a, 0) >= CONFIDENCE_ORDER.get(b, 0) else b


def raw_excerpt(obj: Any, limit: int = 1200) -> Any:
    text = json.dumps(obj, sort_keys=True, default=str)
    if len(text) <= limit:
        try:
            return json.loads(text)
        except Exception:
            return text
    return {"truncated": True, "sha256": sha256_bytes(text.encode()), "prefix": text[:limit]}


def first_location_from_slither(elements: list[dict[str, Any]]) -> dict[str, Any]:
    location: dict[str, Any] = {"file": None, "line": None, "line_end": None, "function": None, "contract": None}
    for el in elements or []:
        src = el.get("source_mapping") or {}
        file = src.get("filename_relative") or src.get("filename_short") or src.get("filename_absolute") or src.get("filename")
        lines = src.get("lines") or []
        line = lines[0] if lines else src.get("line") or src.get("starting_column")
        line_end = lines[-1] if lines else src.get("line_end")
        typ = el.get("type")
        name = el.get("name")
        if typ == "function" and name and not location.get("function"):
            location["function"] = name.split(".")[-1]
        if typ == "contract" and name and not location.get("contract"):
            location["contract"] = name
        if file or line:
            location.update({"file": normalize_path(file), "line": as_int(line), "line_end": as_int(line_end)})
            break
    return location


def normalize_slither(data: Any, input_path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    detectors = (((data or {}).get("results") or {}).get("detectors") or []) if isinstance(data, dict) else []
    for idx, d in enumerate(detectors):
        loc = first_location_from_slither(d.get("elements") or [])
        out.append({
            "tool": "slither",
            "input_path": str(input_path),
            "raw_index": idx,
            "rule_id": str(d.get("check") or d.get("impact") or "unknown"),
            "title": compact(d.get("check") or d.get("impact") or "Slither detector"),
            "message": compact(d.get("description") or d.get("markdown") or d.get("first_markdown_element") or ""),
            "severity_raw": d.get("impact"),
            "confidence_raw": d.get("confidence"),
            "file": loc.get("file"),
            "line": loc.get("line"),
            "line_end": loc.get("line_end"),
            "contract": loc.get("contract"),
            "function": loc.get("function"),
            "raw": d,
        })
    return out


def normalize_semgrep(data: Any, input_path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for idx, r in enumerate((data or {}).get("results") or []):
        extra = r.get("extra") or {}
        metadata = extra.get("metadata") or {}
        start = r.get("start") or {}
        end = r.get("end") or {}
        out.append({
            "tool": "semgrep",
            "input_path": str(input_path),
            "raw_index": idx,
            "rule_id": str(r.get("check_id") or "semgrep-rule"),
            "title": compact(metadata.get("shortlink") or r.get("check_id") or "Semgrep rule"),
            "message": compact(extra.get("message") or ""),
            "severity_raw": extra.get("severity"),
            "confidence_raw": metadata.get("confidence"),
            "file": normalize_path(r.get("path")),
            "line": as_int(start.get("line")),
            "line_end": as_int(end.get("line")),
            "contract": metadata.get("contract"),
            "function": metadata.get("function"),
            "cwe": metadata.get("cwe"),
            "swc": metadata.get("swc"),
            "references": metadata.get("references") or [],
            "raw": r,
        })
    return out


def normalize_mythril(data: Any, input_path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for idx, issue in enumerate((data or {}).get("issues") or []):
        loc = (issue.get("locations") or [{}])[0]
        srcmap = loc.get("sourceMap") or loc.get("source_map") or {}
        out.append({
            "tool": "mythril",
            "input_path": str(input_path),
            "raw_index": idx,
            "rule_id": str(issue.get("swc-id") or issue.get("swcID") or issue.get("title") or "unknown"),
            "title": compact(issue.get("title") or issue.get("swc-id") or "Mythril issue"),
            "message": compact(issue.get("description") or issue.get("title") or ""),
            "severity_raw": issue.get("severity"),
            "confidence_raw": issue.get("confidence") or "symbolic",
            "file": normalize_path(srcmap.get("filename") or loc.get("file")),
            "line": as_int(srcmap.get("lineno") or loc.get("line")),
            "line_end": None,
            "contract": issue.get("contract"),
            "function": issue.get("function"),
            "swc": issue.get("swc-id") or issue.get("swcID"),
            "raw": issue,
        })
    return out


def sarif_rule_map(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    driver = ((run.get("tool") or {}).get("driver") or {})
    rules = {}
    for rule in driver.get("rules") or []:
        rid = rule.get("id") or rule.get("name")
        if rid:
            rules[str(rid)] = rule
    return rules


def normalize_sarif(data: Any, input_path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for run_idx, run in enumerate((data or {}).get("runs") or []):
        tool_name = (((run.get("tool") or {}).get("driver") or {}).get("name") or "sarif").lower()
        rules = sarif_rule_map(run)
        for idx, result in enumerate(run.get("results") or []):
            rid = str(result.get("ruleId") or result.get("rule_id") or "sarif-rule")
            rule = rules.get(rid, {})
            loc = (result.get("locations") or [{}])[0]
            phys = loc.get("physicalLocation") or loc.get("physical_location") or {}
            art = phys.get("artifactLocation") or phys.get("artifact_location") or {}
            region = phys.get("region") or {}
            msg = result.get("message") or {}
            text = msg.get("text") if isinstance(msg, dict) else msg
            out.append({
                "tool": tool_name,
                "input_path": str(input_path),
                "raw_index": f"{run_idx}:{idx}",
                "rule_id": rid,
                "title": compact(rule.get("name") or rid),
                "message": compact(text or rule.get("fullDescription", {}).get("text") or rule.get("shortDescription", {}).get("text") or ""),
                "severity_raw": result.get("level") or (rule.get("properties") or {}).get("severity"),
                "confidence_raw": (rule.get("properties") or {}).get("confidence"),
                "file": normalize_path(art.get("uri") or art.get("uriBaseId")),
                "line": as_int(region.get("startLine")),
                "line_end": as_int(region.get("endLine")),
                "contract": None,
                "function": None,
                "cwe": (rule.get("properties") or {}).get("cwe"),
                "swc": (rule.get("properties") or {}).get("swc"),
                "references": [r.get("uri") for r in rule.get("helpUri", [])] if isinstance(rule.get("helpUri"), list) else [],
                "raw": result,
            })
    return out


def candidate_lists(data: Any) -> Iterable[list[Any]]:
    if isinstance(data, list):
        yield data
    if not isinstance(data, dict):
        return
    for key in ("issues", "findings", "results", "detectors", "vulnerabilities", "warnings", "errors", "high", "medium", "low", "informational"):
        val = data.get(key)
        if isinstance(val, list):
            yield val
        elif isinstance(val, dict):
            for sub in val.values():
                if isinstance(sub, list):
                    yield sub
    for val in data.values():
        if isinstance(val, dict):
            yield from candidate_lists(val)


def normalize_generic(data: Any, input_path: Path, tool: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen = set()
    for items in candidate_lists(data):
        for item in items:
            if not isinstance(item, dict):
                continue
            marker = id(item)
            if marker in seen:
                continue
            seen.add(marker)
            loc = item.get("location") or item.get("source") or item.get("source_mapping") or {}
            line = item.get("line") or item.get("lineno") or loc.get("line") or loc.get("startLine")
            file = item.get("file") or item.get("path") or item.get("filename") or loc.get("file") or loc.get("path") or loc.get("filename")
            out.append({
                "tool": tool,
                "input_path": str(input_path),
                "raw_index": len(out),
                "rule_id": str(item.get("check") or item.get("rule") or item.get("rule_id") or item.get("id") or item.get("type") or item.get("title") or "unknown"),
                "title": compact(item.get("title") or item.get("name") or item.get("check") or item.get("rule") or "Scanner issue"),
                "message": compact(item.get("message") or item.get("description") or item.get("detail") or item.get("title") or ""),
                "severity_raw": item.get("severity") or item.get("impact") or item.get("level"),
                "confidence_raw": item.get("confidence") or item.get("likelihood"),
                "file": normalize_path(file),
                "line": as_int(line),
                "line_end": as_int(item.get("line_end") or item.get("endLine") or loc.get("endLine")),
                "contract": item.get("contract"),
                "function": item.get("function") or item.get("func"),
                "cwe": item.get("cwe"),
                "swc": item.get("swc") or item.get("swc-id") or item.get("swcID"),
                "references": item.get("references") or item.get("links") or [],
                "raw": item,
            })
    return out


def infer_tool(path: Path, data: Any) -> str:
    name = path.name.lower()
    if isinstance(data, dict) and data.get("version") == "2.1.0" and "runs" in data:
        return "sarif"
    if "slither" in name or (isinstance(data, dict) and isinstance(data.get("results"), dict) and "detectors" in data.get("results", {})):
        return "slither"
    if "semgrep" in name or (isinstance(data, dict) and "results" in data and "paths" in data and "version" in data):
        return "semgrep"
    if "myth" in name or (isinstance(data, dict) and "issues" in data and ("success" in data or "mythril" in json.dumps(data)[:1000].lower())):
        return "mythril"
    if "aderyn" in name:
        return "aderyn"
    if "wake" in name:
        return "wake"
    if "solhint" in name:
        return "solhint"
    return "generic"


def classify(raw: dict[str, Any]) -> dict[str, Any]:
    haystack = " ".join(str(raw.get(k) or "") for k in ("tool", "rule_id", "title", "message", "swc", "cwe")).lower()
    for rule in BUG_CLASS_RULES:
        if any(pat.lower() in haystack for pat in rule["patterns"]):
            merged = {**DEFAULT_CLASS, **rule}
            return merged
    return dict(DEFAULT_CLASS)


def noise_reason(raw: dict[str, Any], classification: dict[str, Any]) -> str | None:
    haystack = " ".join(str(raw.get(k) or "") for k in ("rule_id", "title", "message")).lower()
    for patterns, reason in NOISE_RULES:
        if any(pat in haystack for pat in patterns):
            return reason
    if normalize_severity(raw.get("severity_raw")) == "INFO" and classification.get("bug_class") == "scanner-signal":
        return "informational scanner signal without mapped high-impact bug class"
    return None


def load_code_index(path: Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    return load_json(path)


def file_matches(index_file: str, finding_file: str | None) -> bool:
    if not finding_file:
        return False
    a = normalize_path(index_file) or index_file
    b = normalize_path(finding_file) or finding_file
    return a == b or a.endswith("/" + b) or b.endswith("/" + a) or Path(a).name == Path(b).name


def enrich_with_code_index(raw: dict[str, Any], index: dict[str, Any] | None) -> dict[str, Any]:
    if not index:
        return {}
    file = raw.get("file")
    line = as_int(raw.get("line"))
    fn_name = raw.get("function")
    best_contract = None
    best_fn = None
    for contract in index.get("contracts", []):
        if not file_matches(contract.get("file", ""), file):
            continue
        if line and contract.get("line_start", 0) <= line <= contract.get("line_end", 0):
            best_contract = contract
            for fn in contract.get("functions", []):
                if fn.get("line_start", 0) <= line <= fn.get("line_end", 0):
                    best_fn = fn
                    break
        elif fn_name:
            for fn in contract.get("functions", []):
                if fn.get("name") == fn_name:
                    best_contract = contract
                    best_fn = fn
                    break
        if best_contract and (best_fn or not fn_name):
            break
    if not best_contract:
        return {}
    ctx: dict[str, Any] = {
        "contract": best_contract.get("name"),
        "contract_kind": best_contract.get("kind"),
        "contract_id": best_contract.get("id"),
        "bases": best_contract.get("bases", []),
    }
    if best_fn:
        ctx.update({
            "function": best_fn.get("name"),
            "function_id": best_fn.get("id"),
            "function_visibility": best_fn.get("visibility"),
            "state_mutability": best_fn.get("state_mutability"),
            "modifiers": best_fn.get("modifiers", []),
            "auth_checks": best_fn.get("auth_checks", []),
            "value_moving": bool((best_fn.get("asset_flow") or {}).get("value_moving")),
            "asset_flow": best_fn.get("asset_flow"),
            "writes": best_fn.get("writes", []),
            "reads": best_fn.get("reads", []),
            "external_call_count": len(best_fn.get("external_calls", [])),
            "low_level_call_count": len(best_fn.get("low_level_calls", [])),
            "risk_tags": best_fn.get("risk_tags", []),
        })
    return ctx


def proof_profile(classification: dict[str, Any], code_context: dict[str, Any]) -> tuple[str, list[str]]:
    proof = classification.get("proof") or DEFAULT_CLASS["proof"]
    questions = list(classification.get("questions") or DEFAULT_CLASS["questions"])
    if code_context.get("value_moving"):
        questions.append("Code index marks this as value-moving; what exact asset delta proves loss/gain?")
    if code_context.get("writes"):
        questions.append("Which written storage variable is the invariant target?")
    if code_context.get("auth_checks"):
        questions.append("Does the inline auth check restrict normal attackers or is it bypassable?")
    return proof, questions[:8]


def compute_score(severity: str, confidence: str, classification: dict[str, Any], code_context: dict[str, Any], killed: bool) -> dict[str, int | str]:
    impact = min(3, int(classification.get("impact_weight", 1)))
    reachability = 1
    if code_context.get("function_visibility") in {"public", "external"}:
        reachability += 1
    if code_context.get("value_moving"):
        reachability += 1
    reachability = min(3, reachability)
    poc = min(3, int(classification.get("poc_weight", 1)))
    scope = 1
    novelty = 1
    economics = 1 + (1 if classification.get("impact_type") in {"stolen-funds", "bad-debt", "frozen-funds"} else 0) + (1 if code_context.get("value_moving") else 0)
    economics = min(3, economics)
    deductions = 0
    if killed:
        deductions -= 6
    if severity in {"UNKNOWN", "INFO"}:
        deductions -= 1
    if confidence in {"UNKNOWN", "LOW"}:
        deductions -= 1
    if classification.get("chain_required"):
        deductions -= 2
    total = impact + reachability + poc + scope + novelty + economics + deductions
    return {
        "impact": impact,
        "reachability": reachability,
        "poc_simplicity": poc,
        "scope_match": scope,
        "novelty": novelty,
        "economic_realism": economics,
        "deductions": deductions,
        "total": total,
        "rationale": "scanner severity/confidence plus code-index reachability/value-flow hints; proof still required",
    }


def make_lead(raw: dict[str, Any], index: dict[str, Any] | None) -> dict[str, Any]:
    classification = classify(raw)
    code_context = enrich_with_code_index(raw, index)
    if code_context.get("contract") and not raw.get("contract"):
        raw["contract"] = code_context["contract"]
    if code_context.get("function") and not raw.get("function"):
        raw["function"] = code_context["function"]
    severity = normalize_severity(raw.get("severity_raw"))
    confidence = normalize_confidence(raw.get("confidence_raw"))
    reason = noise_reason(raw, classification)
    killed = bool(reason)
    if killed and code_context.get("value_moving") and classification.get("bug_class") != "scanner-signal":
        killed = False
        reason = None
    if classification.get("chain_required") and not killed:
        status = "CHAIN_REQUIRED"
        triage_verdict = "CHAIN_REQUIRED"
    elif killed:
        status = "KILL"
        triage_verdict = "KILL"
    else:
        status = "LEAD"
        triage_verdict = "LEAD"
    proof, questions = proof_profile(classification, code_context)
    file = raw.get("file")
    line = as_int(raw.get("line"))
    contract = raw.get("contract") or "<unknown>"
    fn = raw.get("function") or "<unknown>"
    bug_class = classification["bug_class"]
    group_key = f"{contract} | {fn} | {bug_class}"
    dedupe_material = {"bug_class": bug_class, "file": file, "line": line, "contract": raw.get("contract"), "function": raw.get("function")}
    dedupe_key = stable_hash(dedupe_material, 20)
    fingerprint = stable_hash({**dedupe_material, "tool": raw.get("tool"), "rule_id": raw.get("rule_id"), "message": raw.get("message")}, 20)
    lead = {
        "id": f"S-{fingerprint[:12]}",
        "tool": raw.get("tool") or "unknown",
        "tools": [raw.get("tool") or "unknown"],
        "input_path": raw.get("input_path"),
        "raw_index": str(raw.get("raw_index")),
        "rule_id": raw.get("rule_id") or "unknown",
        "title": compact(raw.get("title") or f"{bug_class} signal", 220),
        "bug_class": bug_class,
        "category": classification.get("category"),
        "severity": severity,
        "confidence": confidence,
        "status": status,
        "triage_verdict": triage_verdict,
        "file": file,
        "line": line,
        "line_end": as_int(raw.get("line_end")),
        "contract": raw.get("contract"),
        "function": raw.get("function"),
        "message": compact(raw.get("message") or raw.get("title") or "", 1200),
        "impact_type": classification.get("impact_type") if classification.get("impact_type") in IMPACT_TYPES else "unknown",
        "impact_hint": classification.get("impact_type") if classification.get("impact_type") in IMPACT_TYPES else "unknown",
        "proof_needed": proof,
        "proof_questions": questions,
        "exploit_hypothesis": f"Because {contract}.{fn} has a {bug_class} scanner signal, test whether a normal attacker can execute ordered steps causing {classification.get('impact_type', 'accepted impact')}.",
        "dedupe_key": dedupe_key,
        "group_key": group_key,
        "fingerprint": fingerprint,
        "tags": sorted(set(["scanner", raw.get("tool") or "unknown", *classification.get("tags", [])])),
        "code_context": code_context,
        "suppression": {"reason": reason, "kind": "noise-filter"} if reason else None,
        "score": compute_score(severity, confidence, classification, code_context, killed),
        "references": raw.get("references") or [],
        "cwe": raw.get("cwe"),
        "swc": raw.get("swc"),
        "raw_excerpt": raw_excerpt(raw.get("raw")),
    }
    return lead


def dedupe_leads(leads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for lead in leads:
        key = lead["dedupe_key"]
        if key not in merged:
            merged[key] = lead
            merged[key]["merged_count"] = 1
            merged[key]["merged_fingerprints"] = [lead["fingerprint"]]
            continue
        current = merged[key]
        current["merged_count"] += 1
        current["merged_fingerprints"].append(lead["fingerprint"])
        current["tools"] = sorted(set(current.get("tools", []) + lead.get("tools", [])))
        current["tool"] = "+".join(current["tools"])
        current["severity"] = max_severity(current["severity"], lead["severity"])
        current["confidence"] = max_confidence(current["confidence"], lead["confidence"])
        current["message"] = compact(current.get("message", "") + " | " + lead.get("message", ""), 1600)
        if current.get("status") == "KILL" and lead.get("status") != "KILL":
            current["status"] = lead["status"]
            current["triage_verdict"] = lead["triage_verdict"]
            current["suppression"] = None
        if int(lead.get("score", {}).get("total", 0)) > int(current.get("score", {}).get("total", 0)):
            current["score"] = lead["score"]
        current["references"] = sorted(set(current.get("references", []) + lead.get("references", [])))
    return sorted(merged.values(), key=lambda l: (l.get("status") == "KILL", -int(l.get("score", {}).get("total", 0)), l.get("file") or "", l.get("line") or 0))


def normalize_file(path: Path, forced_tool: str, index: dict[str, Any] | None) -> tuple[str, list[dict[str, Any]]]:
    data = load_json(path)
    tool = infer_tool(path, data) if forced_tool == "auto" else forced_tool
    if tool == "slither":
        raw = normalize_slither(data, path)
    elif tool == "semgrep":
        raw = normalize_semgrep(data, path)
    elif tool == "mythril":
        raw = normalize_mythril(data, path)
    elif tool == "sarif":
        raw = normalize_sarif(data, path)
    else:
        raw = normalize_generic(data, path, tool)
    return tool, [make_lead(item, index) for item in raw]


def summary(leads: list[dict[str, Any]], raw_count: int) -> dict[str, Any]:
    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_bug_class: dict[str, int] = {}
    for lead in leads:
        by_status[lead["status"]] = by_status.get(lead["status"], 0) + 1
        by_severity[lead["severity"]] = by_severity.get(lead["severity"], 0) + 1
        by_bug_class[lead["bug_class"]] = by_bug_class.get(lead["bug_class"], 0) + 1
    return {
        "raw_count": raw_count,
        "normalized_count": len(leads),
        "lead_count": sum(1 for l in leads if l.get("status") == "LEAD"),
        "chain_required_count": sum(1 for l in leads if l.get("status") == "CHAIN_REQUIRED"),
        "killed_count": sum(1 for l in leads if l.get("status") == "KILL"),
        "by_status": dict(sorted(by_status.items())),
        "by_severity": dict(sorted(by_severity.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 0), reverse=True)),
        "by_bug_class": dict(sorted(by_bug_class.items())),
        "top_leads": [
            {"id": l["id"], "status": l["status"], "score": l["score"]["total"], "bug_class": l["bug_class"], "location": f"{l.get('file') or '-'}:{l.get('line') or '-'}"}
            for l in sorted([x for x in leads if x.get("status") != "KILL"], key=lambda x: x.get("score", {}).get("total", 0), reverse=True)[:10]
        ],
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    code_index = load_code_index(args.code_index)
    all_leads: list[dict[str, Any]] = []
    inputs = []
    raw_count = 0
    for path in args.inputs:
        tool, leads = normalize_file(path, args.tool, code_index)
        raw_count += len(leads)
        inputs.append({"path": str(path), "sha256": sha256_file(path), "tool": tool, "raw_count": len(leads)})
        all_leads.extend(leads)
    leads = dedupe_leads(all_leads) if not args.no_dedupe else all_leads
    if not args.include_killed:
        visible = [l for l in leads if l.get("status") != "KILL"]
        suppressed = [l for l in leads if l.get("status") == "KILL"]
    else:
        visible = leads
        suppressed = [l for l in leads if l.get("status") == "KILL"]
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "inputs": inputs,
        "normalizer": {
            "dedupe": not args.no_dedupe,
            "include_killed_in_leads": bool(args.include_killed),
            "code_index": str(args.code_index) if args.code_index else None,
        },
        "summary": summary(leads, raw_count),
        "leads": visible,
        "suppressed": suppressed,
    }
    return report


def legacy_rows(report: dict[str, Any], include_killed: bool = False) -> list[dict[str, Any]]:
    rows = list(report.get("leads", []))
    if include_killed and not (report.get("normalizer") or {}).get("include_killed_in_leads"):
        rows += list(report.get("suppressed", []))
    return rows


def print_markdown(report: dict[str, Any], limit: int) -> None:
    s = report["summary"]
    print("# Normalized Scanner Leads")
    print()
    print(f"Raw findings: {s['raw_count']} | Normalized groups: {s['normalized_count']} | Leads: {s['lead_count']} | Chain required: {s['chain_required_count']} | Killed/suppressed: {s['killed_count']}")
    print()
    print("## Top Lead Candidates")
    print()
    print("| Status | Score | Tool | Bug class | Severity | Confidence | Location | Message |")
    print("|---|---:|---|---|---|---|---|---|")
    for lead in [l for l in report.get("leads", []) if l.get("status") != "KILL"][:limit]:
        loc = f"{lead.get('file') or '-'}:{lead.get('line') or '-'}"
        print(f"| {lead['status']} | {lead['score']['total']} | {lead['tool']} | `{lead['bug_class']}` | {lead['severity']} | {lead['confidence']} | {loc} | {compact(lead.get('message'), 180)} |")
    if report.get("suppressed"):
        print()
        print("## Suppressed / Killed Scanner Noise")
        print()
        for lead in report.get("suppressed", [])[:limit]:
            loc = f"{lead.get('file') or '-'}:{lead.get('line') or '-'}"
            reason = (lead.get("suppression") or {}).get("reason") or "suppressed"
            print(f"- `{lead['rule_id']}` at {loc}: {reason}")
    print()
    print("Every non-suppressed row is still only a lead. Promote only after manual reachability, concrete impact, and PoC assertions.")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Normalize Web3 scanner JSON into Lead DB-ready rows")
    ap.add_argument("inputs", type=Path, nargs="+", help="scanner JSON/SARIF files")
    ap.add_argument("--tool", default="auto", choices=["auto", "slither", "semgrep", "mythril", "aderyn", "sarif", "wake", "solhint", "generic"])
    ap.add_argument("--code-index", type=Path, help="optional x-ray/code-index.json for context enrichment")
    ap.add_argument("--json", dest="json_path", help="write canonical normalization report JSON")
    ap.add_argument("--leads-json", dest="leads_json_path", help="write legacy list of Lead DB-ready rows")
    ap.add_argument("--include-killed", action="store_true", help="include suppressed KILL rows in report.leads as well as report.suppressed")
    ap.add_argument("--no-dedupe", action="store_true", help="do not merge duplicate scanner rows")
    ap.add_argument("--markdown-limit", type=int, default=25)
    return ap


def main() -> int:
    args = build_parser().parse_args()
    report = build_report(args)
    if args.json_path:
        Path(args.json_path).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_path).write_text(json.dumps(report, indent=2) + "\n")
    if args.leads_json_path:
        Path(args.leads_json_path).parent.mkdir(parents=True, exist_ok=True)
        Path(args.leads_json_path).write_text(json.dumps(legacy_rows(report, include_killed=args.include_killed), indent=2) + "\n")
    print_markdown(report, args.markdown_limit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
