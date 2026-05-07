#!/usr/bin/env python3
"""Structured evidence extraction for blind Solidity leads."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from solidity_fixture_indexer import find_matching_brace, index_project


def snippet(body: str, max_lines: int = 12) -> str:
    lines = [line.rstrip() for line in body.strip().splitlines()]
    return "\n".join(lines[:max_lines])


def strip_comments(text: str) -> str:
    text = re.sub(r"//.*", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return text


def externally_callable(fn: dict[str, Any]) -> bool:
    """Return True for public/external functions, including old Solidity defaults."""
    if fn.get("name") == "constructor":
        return False
    visibility = fn.get("visibility") or ""
    return visibility in {"", "public", "external"}


def guarded_by_owner_or_role(fn: dict[str, Any], code: str) -> bool:
    return bool(
        re.search(r"require\s*\(\s*msg\.sender\s*==\s*owner", code)
        or re.search(r"if\s*\(\s*msg\.sender\s*!=\s*owner\s*\)\s*(?:throw|revert)", code)
        or any("owner" in m.lower() or "role" in m.lower() for m in fn.get("modifiers", []))
    )


def line_matches(body: str, pattern: str, start_line: int) -> list[int]:
    return [start_line + idx for idx, line in enumerate(body.splitlines()) if re.search(pattern, line)]


def function_evidence(file_path: str, contract: dict[str, Any], fn: dict[str, Any], rule: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "file_path": file_path,
        "contract": contract["name"],
        "function": fn["name"],
        "line_start": fn["start_line"],
        "line_end": fn["end_line"],
        "rule": rule,
        "snippet": snippet(fn.get("body", "")),
        "details": details or {},
    }


def project_evidence(file_path: str, contract: str, function: str, line_start: int, line_end: int, rule: str, body: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "file_path": file_path,
        "contract": contract,
        "function": function,
        "line_start": line_start,
        "line_end": line_end,
        "rule": rule,
        "snippet": snippet(body),
        "details": details or {},
    }


def require_core_evidence(ev: dict[str, Any]) -> None:
    for field in ["file_path", "contract", "function", "line_start", "line_end", "snippet"]:
        if not ev.get(field):
            raise SystemExit(f"evidence missing {field}")


def extract_reentrancy_evidence(file_path: str, contract: dict[str, Any], fn: dict[str, Any]) -> dict[str, Any] | None:
    body = fn.get("body", "")
    code = strip_comments(body)
    external_match = re.search(r"\.call\s*\{\s*value\s*:|\.call\.value\s*\(", code)
    if not external_match:
        return None
    state_update = re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\[\s*msg\.sender\s*\]\s*(?:=\s*0|-=)", code[external_match.end():])
    if state_update:
        ev = function_evidence(file_path, contract, fn, "external_call_before_state_update", {"external_call_lines": line_matches(body, r"\.call\s*\{\s*value\s*:|\.call\.value\s*\(", fn["start_line"]), "state_update_lines": line_matches(body, r"\[\s*msg\.sender\s*\]\s*(?:=\s*0|-=)", fn["start_line"])})
        require_core_evidence(ev)
        return ev
    return None


def extract_cross_function_reentrancy_evidence(file_path: str, contract: dict[str, Any], fn: dict[str, Any], contract_body: str) -> dict[str, Any] | None:
    body = fn.get("body", "")
    code = strip_comments(body)
    if ".call{value:" not in code:
        return None
    if "balanceOf[msg.sender]" in code:
        return None
    mapping_updates = list(re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*msg\.sender\s*\]\s*=\s*0", code))
    if not mapping_updates:
        return None
    external = code.find(".call{value:")
    stale_names = [m.group(1) for m in mapping_updates if m.start() > external]
    if not stale_names:
        return None
    sibling_reads_stale = False
    stripped_contract = strip_comments(contract_body)
    for name in stale_names:
        reads = len(re.findall(rf"\b{re.escape(name)}\s*\[\s*msg\.sender\s*\]", stripped_contract))
        if reads >= 2 and re.search(r"\.(?:transfer|call)\s*(?:\{|\()", stripped_contract):
            sibling_reads_stale = True
            break
    if not sibling_reads_stale:
        return None
    ev = function_evidence(file_path, contract, fn, "cross_function_reentrancy_stale_accounting", {"external_call_lines": line_matches(body, r"\.call\{value:", fn["start_line"]), "state_update_lines": line_matches(body, r"\[\s*msg\.sender\s*\]\s*=\s*0", fn["start_line"]), "stale_mappings": stale_names})
    require_core_evidence(ev)
    return ev


def extract_initializer_evidence(file_path: str, contract: dict[str, Any], fn: dict[str, Any]) -> dict[str, Any] | None:
    body = fn.get("body", "")
    code = strip_comments(body)
    named_like_constructor = fn.get("name") and fn.get("name") == contract.get("name")
    assigns_owner = re.search(r"\bowner\s*=\s*(?:_?owner|msg\.sender)\b", code)
    if externally_callable(fn) and assigns_owner and not named_like_constructor and "initialized" not in code and "initializer" not in " ".join(fn.get("modifiers", [])):
        ev = function_evidence(file_path, contract, fn, "initializer_without_guard", {"owner_assignment_lines": line_matches(body, r"owner\s*=", fn["start_line"])})
        require_core_evidence(ev)
        return ev
    return None


def extract_signature_evidence(file_path: str, contract: dict[str, Any], fn: dict[str, Any], contract_body: str) -> dict[str, Any] | None:
    body = fn.get("body", "")
    code = strip_comments(body)
    contract_code = strip_comments(contract_body)
    if fn.get("visibility") in {"external", "public"} and "signature" in code and ("ecrecover" in contract_code or "_recover" in code):
        missing = [field for field in ["nonce", "deadline", "chainid", "address(this)"] if field.lower() not in contract_code.lower()]
        if missing:
            ev = function_evidence(file_path, contract, fn, "signature_without_nonce_domain_deadline", {"missing_fields": missing, "signature_lines": line_matches(body, r"signature|recover|ecrecover", fn["start_line"])})
            require_core_evidence(ev)
            return ev
    return None


def extract_bridge_evidence(file_path: str, contract: dict[str, Any], fn: dict[str, Any]) -> dict[str, Any] | None:
    body = fn.get("body", "")
    code = strip_comments(body)
    consumed_set = code.find("consumed[messageId] = true")
    callback = code.find("onFinalize")
    transfer = code.find("token.transfer")
    if "consumed[messageId]" in body and consumed_set >= 0 and ((callback >= 0 and consumed_set > callback) or (transfer >= 0 and consumed_set > transfer)):
        ev = function_evidence(file_path, contract, fn, "consumed_message_set_after_external_interaction", {"consumed_lines": line_matches(body, r"consumed\[messageId\]", fn["start_line"]), "callback_lines": line_matches(body, r"onFinalize|transfer", fn["start_line"])})
        require_core_evidence(ev)
        return ev
    return None


def extract_erc4626_evidence(file_path: str, contract: dict[str, Any], fn: dict[str, Any]) -> dict[str, Any] | None:
    body = fn.get("body", "")
    code = strip_comments(body)
    if re.search(r"supply\s*==\s*0\s*\?\s*assets", code) and "transferFrom" in code and "virtual" not in code.lower() and "minShares" not in code:
        ev = function_evidence(file_path, contract, fn, "erc4626_first_depositor_donation_inflation", {"share_calc_lines": line_matches(body, r"shares\s*=|totalAssets", fn["start_line"])})
        require_core_evidence(ev)
        return ev
    return None


def extract_reward_evidence(file_path: str, contract: dict[str, Any], fn: dict[str, Any], contract_body: str) -> dict[str, Any] | None:
    body = fn.get("body", "")
    code = strip_comments(body)
    contract_code = strip_comments(contract_body)
    if "rewardPool" in code and "staked[msg.sender]" in code and "totalStaked" in code and "rewardToken.transfer" in code and "rewardDebt" not in contract_code and "accRewardPerShare" not in contract_code:
        ev = function_evidence(file_path, contract, fn, "reward_pool_current_balance_accounting", {"reward_calc_lines": line_matches(body, r"rewardPool|staked\[msg\.sender\]|totalStaked", fn["start_line"])})
        require_core_evidence(ev)
        return ev
    return None


def extract_oracle_evidence(file_path: str, contract: dict[str, Any], fn: dict[str, Any], project_index: dict[str, Any]) -> dict[str, Any] | None:
    body = fn.get("body", "")
    project_text = strip_comments("\n".join(f.get("text", "") for f in project_index.get("files", []) if f.get("kind") == "solidity"))
    unrestricted_setter = False
    for setter in re.finditer(r"function\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*(?:price|newPrice)[^)]*\)\s*external\s*\{(?P<body>[^}]*)\}", project_text, re.S):
        setter_body = setter.group("body")
        if "price" in setter_body and not re.search(r"require\s*\(|onlyOwner|msg\.sender\s*==\s*owner", setter_body):
            unrestricted_setter = True
    if "oracle.price()" in body and "debt.transfer" in body and unrestricted_setter:
        ev = function_evidence(file_path, contract, fn, "borrow_uses_public_mutable_oracle_price", {"oracle_read_lines": line_matches(body, r"oracle\.price\(\)", fn["start_line"]), "asset_transfer_lines": line_matches(body, r"debt\.transfer", fn["start_line"])})
        require_core_evidence(ev)
        return ev
    return None


def extract_access_control_evidence(file_path: str, contract: dict[str, Any], fn: dict[str, Any]) -> dict[str, Any] | None:
    body = fn.get("body", "")
    code = strip_comments(body)
    contract_body = strip_comments(contract.get("body", ""))
    has_owner_model = "owner" in contract_body and re.search(r"require\s*\(\s*msg\.sender\s*==\s*owner", contract_body)
    mutates_assets = re.search(r"\b(asset|token)\.transfer\s*\(\s*(to|receiver|msg\.sender)", code)
    guarded = guarded_by_owner_or_role(fn, code)
    if has_owner_model and mutates_assets and not guarded:
        ev = function_evidence(file_path, contract, fn, "missing_access_control_on_privileged_asset_transfer", {"transfer_lines": line_matches(body, r"\.transfer", fn["start_line"]), "sibling_owner_guard_exists": True})
        require_core_evidence(ev)
        return ev
    return None


def extract_unprotected_selfdestruct_evidence(file_path: str, contract: dict[str, Any], fn: dict[str, Any]) -> dict[str, Any] | None:
    body = fn.get("body", "")
    code = strip_comments(body)
    if externally_callable(fn) and re.search(r"\b(?:selfdestruct|suicide)\s*\(", code) and not guarded_by_owner_or_role(fn, code):
        ev = function_evidence(file_path, contract, fn, "unprotected_selfdestruct", {"destruct_lines": line_matches(body, r"selfdestruct|suicide", fn["start_line"])})
        require_core_evidence(ev)
        return ev
    return None


def extract_owner_assignment_evidence(file_path: str, contract: dict[str, Any], fn: dict[str, Any]) -> dict[str, Any] | None:
    body = fn.get("body", "")
    code = strip_comments(body)
    contract_body = strip_comments(contract.get("body", ""))
    constructor_names = {"constructor", str(contract.get("name", ""))}
    has_owner_state = re.search(r"\baddress\s+(?:public\s+|private\s+|internal\s+)?owner\b", contract_body) or "owner" in contract_body
    assigns_owner = re.search(r"\bowner\s*=\s*(?:msg\.sender|_[A-Za-z0-9_]+|[A-Za-z_][A-Za-z0-9_]*)", code)
    if externally_callable(fn) and fn.get("name") not in constructor_names and has_owner_state and assigns_owner and "initialized" not in code and not guarded_by_owner_or_role(fn, code):
        ev = function_evidence(file_path, contract, fn, "public_owner_assignment_without_guard", {"owner_assignment_lines": line_matches(body, r"owner\s*=", fn["start_line"])})
        require_core_evidence(ev)
        return ev
    return None


def extract_token_accounting_evidence(file_path: str, contract: dict[str, Any], fn: dict[str, Any]) -> dict[str, Any] | None:
    body = fn.get("body", "")
    code = strip_comments(body)
    if "transferFrom" in code and re.search(r"credited\[msg\.sender\]\s*\+=\s*amount", code) and "balanceBefore" not in code and "received" not in code:
        ev = function_evidence(file_path, contract, fn, "credits_requested_amount_not_balance_delta", {"credit_lines": line_matches(body, r"credited\[msg\.sender\]|transferFrom", fn["start_line"])})
        require_core_evidence(ev)
        return ev
    return None


def extract_decimal_normalization_evidence(file_path: str, contract: dict[str, Any], fn: dict[str, Any], contract_body: str) -> dict[str, Any] | None:
    body = fn.get("body", "")
    code = strip_comments(body)
    contract_code = strip_comments(contract_body)
    has_decimal_context = re.search(r"decimals\s*=\s*(6|8)|collateralDecimals|assetDecimals", contract_code)
    uses_price_math = re.search(r"\b(price|answer)\b", code) and re.search(r"/\s*1e18|/\s*10\s*\*\*\s*18", code)
    moves_debt = re.search(r"\b(?:debtToken|debt|asset|token)\.transfer\s*\(\s*msg\.sender", code)
    normalized = re.search(r"10\s*\*\*|collateralDecimals|assetDecimals|scale|normalize|_to18", code, re.I)
    if has_decimal_context and uses_price_math and moves_debt and not normalized:
        ev = function_evidence(file_path, contract, fn, "decimal_normalization_mismatch", {"price_math_lines": line_matches(body, r"price|1e18|10\s*\*\*", fn["start_line"]), "transfer_lines": line_matches(body, r"\.transfer", fn["start_line"])})
        require_core_evidence(ev)
        return ev
    return None


def extract_arithmetic_evidence(file_path: str, contract: dict[str, Any], fn: dict[str, Any], contract_body: str) -> dict[str, Any] | None:
    body = fn.get("body", "")
    code = strip_comments(body)
    full = strip_comments(contract_body)
    if "SafeMath" in full or re.search(r"pragma\s+solidity\s+[^;]*0\.8|>=\s*0\.8", full) or not externally_callable(fn):
        return None
    balance_math = re.search(r"\b(?:balanceOf|balances|sellerBalance|totalSupply)\b[^;]*(?:\+=|-=|\+\s*=|-\s*=)", code)
    unchecked_add = re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*(?:\[[^\]]+\])?\s*\+=\s*[A-Za-z_][A-Za-z0-9_]*", code)
    if balance_math or unchecked_add:
        ev = function_evidence(file_path, contract, fn, "unchecked_arithmetic_pre_solidity_08", {"arithmetic_lines": line_matches(body, r"\+=|-=", fn["start_line"])})
        require_core_evidence(ev)
        return ev
    return None


def extract_randomness_evidence(file_path: str, contract: dict[str, Any], fn: dict[str, Any], contract_body: str) -> dict[str, Any] | None:
    body = fn.get("body", "")
    code = strip_comments(body)
    random_source = re.search(r"\b(?:blockhash|block\.blockhash|block\.timestamp|block\.number|block\.difficulty|now)\b", code)
    random_context = re.search(r"\b(?:random|seed|answer|won|lottery|bet)\b", code, re.I)
    if random_source and random_context:
        ev = function_evidence(file_path, contract, fn, "miner_controlled_randomness", {"randomness_lines": line_matches(body, r"blockhash|block\.blockhash|block\.timestamp|block\.number|block\.difficulty|now|keccak", fn["start_line"])})
        require_core_evidence(ev)
        return ev
    return None


def extract_unchecked_low_level_call_evidence(file_path: str, contract: dict[str, Any], fn: dict[str, Any], contract_body: str) -> dict[str, Any] | None:
    body = fn.get("body", "")
    code = strip_comments(body)
    if not externally_callable(fn):
        return None
    for match in re.finditer(r"[^;\n]*(?:\.call\s*\(|\.send\s*\()[^;]*;", code):
        stmt = match.group(0)
        if re.search(r"\b(require|assert)\s*\(|\bif\s*\(|\bbool\s+|=", stmt):
            continue
        ev = function_evidence(file_path, contract, fn, "unchecked_low_level_call_return", {"call_lines": line_matches(body, r"\.call\s*\(|\.send\s*\(", fn["start_line"])})
        require_core_evidence(ev)
        return ev
    return None


def proof_var_checked(code: str, proof_var: str) -> bool:
    escaped = re.escape(proof_var)
    tail = proof_var.split(".")[-1]
    return bool(
        re.search(rf"\brequire\s*\([^;]*{escaped}\s*\.\s*length", code, re.S)
        or re.search(rf"\b{escaped}\s*\.\s*length\s*(?:==|!=|>=|>|<=|<)", code)
        or re.search(rf"\b{re.escape(tail)}(?:Length|Len)\b", code)
    )


def extract_proof_validation_completeness_evidence(file_path: str, contract: dict[str, Any], fn: dict[str, Any]) -> dict[str, Any] | None:
    body = fn.get("body", "")
    code = strip_comments(body)
    if "verifyInclusion" not in code and "processInclusionProof" not in code:
        return None
    proof_vars: list[str] = []
    for match in re.finditer(r"\b(?:[A-Za-z_][A-Za-z0-9_]*\.)?(?:verifyInclusion(?:Sha256|Keccak)?|processInclusionProof(?:Sha256|Keccak)?)\s*\(\s*([^,\)]+)", code):
        candidate = match.group(1).strip()
        if re.search(r"proof", candidate, re.I) and candidate not in proof_vars:
            proof_vars.append(candidate)
    if len(proof_vars) < 2:
        return None
    checked = [var for var in proof_vars if proof_var_checked(code, var)]
    unchecked = [var for var in proof_vars if var not in checked]
    # A high-signal partial-validation pattern: some dynamic proofs are length-checked,
    # while sibling proof fields consumed by the same verifier are not.
    if checked and unchecked:
        ev = function_evidence(file_path, contract, fn, "missing_dynamic_proof_length_validation", {"checked_proof_vars": checked, "unchecked_proof_vars": unchecked, "verifier_lines": line_matches(body, r"verifyInclusion|processInclusionProof", fn["start_line"])})
        require_core_evidence(ev)
        return ev
    return None


def loop_primary_index(loop_header: str) -> str | None:
    match = re.search(r"for\s*\(\s*(?:uint(?:256)?\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", loop_header)
    return match.group(1) if match else None


def increments_index(text: str, index: str) -> bool:
    escaped = re.escape(index)
    return bool(re.search(rf"(?:\+\+\s*{escaped}|{escaped}\s*\+\+|{escaped}\s*\+=\s*1)", text))


def extract_loop_skip_progress_evidence(file_path: str, contract: dict[str, Any], fn: dict[str, Any]) -> dict[str, Any] | None:
    body = fn.get("body", "")
    code = strip_comments(body)
    if "skip" not in code.lower() or "for" not in code:
        return None
    for match in re.finditer(r"for\s*\([^;]*;[^;]*;\s*\)\s*\{", code, re.S):
        idx = loop_primary_index(match.group(0))
        if not idx:
            continue
        open_brace = match.end() - 1
        close_brace = find_matching_brace(code, open_brace)
        loop_body = code[open_brace + 1:close_brace]
        branch = re.search(r"if\s*\([^)]*skip[^)]*\)\s*\{(?P<if_body>.*?)\}\s*else\s*\{(?P<else_body>.*)\}\s*$", loop_body, re.S | re.I)
        if not branch:
            branch = re.search(r"if\s*\([^)]*skip[^)]*\)\s*\{(?P<if_body>.*?)\}\s*else\s*\{(?P<else_body>.*?)\}", loop_body, re.S | re.I)
        if not branch:
            continue
        if_body = branch.group("if_body")
        else_body = branch.group("else_body")
        if not increments_index(if_body, idx) and increments_index(else_body, idx):
            ev = function_evidence(file_path, contract, fn, "skip_branch_does_not_advance_loop_index", {"loop_index": idx, "loop_lines": line_matches(body, r"for\s*\(|skip", fn["start_line"])})
            require_core_evidence(ev)
            return ev
    return None


def extract_all_or_nothing_external_component_evidence(file_path: str, contract: dict[str, Any], fn: dict[str, Any]) -> dict[str, Any] | None:
    body = fn.get("body", "")
    code = strip_comments(body)
    if not re.search(r"\b(for|while)\b", code):
        return None
    external_component_call = re.search(r"\[[^\]]+\]\s*\.\s*(?:withdraw|redeem|release|execute|claim|finalize)\s*\(", code)
    irreversible_queue_context = re.search(r"withdrawalRootPending\s*\[[^\]]+\]\s*=\s*false|pending\s*\[[^\]]+\]\s*=\s*false|delete\s+pending", code)
    no_partial_escape = not re.search(r"skip|ignore|try\s+|catch\s+|cancel", code, re.I)
    function_context = re.search(r"complete|finalize|withdraw|redeem|claim", fn.get("name", ""), re.I)
    if external_component_call and irreversible_queue_context and no_partial_escape and function_context:
        ev = function_evidence(file_path, contract, fn, "all_or_nothing_external_component_withdrawal", {"external_call_lines": line_matches(body, r"\]\s*\.\s*(?:withdraw|redeem|release|execute|claim|finalize)\s*\(", fn["start_line"]), "pending_state_lines": line_matches(body, r"pending|withdrawalRootPending|delete", fn["start_line"])})
        require_core_evidence(ev)
        return ev
    return None


def project_files(index: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in index.get("files", []) if row.get("kind") == "solidity" and not row.get("path", "").startswith("test/")]


def extract_lifecycle_accounting_evidence(project_index: dict[str, Any]) -> list[dict[str, Any]]:
    files = project_files(project_index)
    project_text = strip_comments("\n".join(str(row.get("text", "")) for row in files))
    has_temporary_debit = re.search(r"\b(?:debt|pendingDebit|decrement\w*Withdrawal|temporary\w*Debit|overcommit\w*)\b", project_text, re.I)
    has_decrease = re.search(r"\b(?:decrease\w*Shares|_removeShares|burn\w*Shares|debit\w*)\s*\(", project_text)
    has_later_credit = re.search(r"\b(?:increase\w*Shares|_addShares|restake\w*|credit\w*|restore\w*)\s*\(", project_text)
    if not (has_temporary_debit and has_decrease and has_later_credit):
        return []
    rows: list[dict[str, Any]] = []
    for file_row in files:
        for contract in file_row.get("contracts", []):
            if contract.get("kind") == "interface":
                continue
            for fn in contract.get("functions", []):
                name = str(fn.get("name", ""))
                body = strip_comments(fn.get("body", ""))
                if not re.search(r"slash|penal|liquidat|punish|seize", name, re.I):
                    continue
                if not re.search(r"\b(?:decrease\w*Shares|_removeShares|withdraw|burn|transfer)\s*\(", body):
                    continue
                if re.search(r"debt|pendingDebit|decrement\w*Withdrawal|temporary\w*Debit|overcommit", body, re.I):
                    continue
                ev = function_evidence(file_row["path"], contract, fn, "temporary_accounting_debit_not_considered_in_slash", {"project_signals": ["temporary debit/debt state", "share decrease path", "later share credit/restake path"], "slash_function": name})
                require_core_evidence(ev)
                rows.append(ev)
    return rows


EXTRACTORS = [
    extract_reentrancy_evidence,
    extract_initializer_evidence,
    extract_bridge_evidence,
    extract_erc4626_evidence,
    extract_access_control_evidence,
    extract_unprotected_selfdestruct_evidence,
    extract_owner_assignment_evidence,
    extract_token_accounting_evidence,
    extract_proof_validation_completeness_evidence,
    extract_loop_skip_progress_evidence,
    extract_all_or_nothing_external_component_evidence,
]


def extract_all_evidence(project_root: Path, *, include_tests: bool = False) -> dict[str, Any]:
    index = index_project(project_root, include_tests=include_tests)
    evidence: list[dict[str, Any]] = []
    for file_row in index.get("files", []):
        if file_row.get("kind") != "solidity" or file_row.get("path", "").startswith("test/"):
            continue
        for contract in file_row.get("contracts", []):
            if contract.get("kind") == "interface":
                continue
            for fn in contract.get("functions", []):
                for extractor in EXTRACTORS:
                    ev = extractor(file_row["path"], contract, fn)  # type: ignore[misc]
                    if ev:
                        evidence.append(ev)
                for extractor in [extract_signature_evidence, extract_reward_evidence, extract_cross_function_reentrancy_evidence, extract_decimal_normalization_evidence]:
                    ev = extractor(file_row["path"], contract, fn, contract.get("body", ""))
                    if ev:
                        evidence.append(ev)
                for extractor in [extract_arithmetic_evidence, extract_randomness_evidence, extract_unchecked_low_level_call_evidence]:
                    ev = extractor(file_row["path"], contract, fn, file_row.get("text", ""))
                    if ev:
                        evidence.append(ev)
                ev = extract_oracle_evidence(file_row["path"], contract, fn, index)
                if ev:
                    evidence.append(ev)
    evidence.extend(extract_lifecycle_accounting_evidence(index))
    return {"project_root": str(project_root), "read_files": index["read_files"], "evidence": evidence}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Extract structured source evidence without answer keys")
    p.add_argument("project_root")
    p.add_argument("--include-tests", action="store_true")
    args = p.parse_args(argv)
    print(json.dumps(extract_all_evidence(Path(args.project_root), include_tests=args.include_tests), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
