#!/usr/bin/env python3
"""Post-freeze source diff analyzer for Proof-of-Patch controls.

This module is intentionally scoring/adjudication-only. It requires frozen
detector outputs for both sides of a pair and never creates report-ready
findings.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT, load_case_outputs


FUNCTION_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)[^{;]*(?:\{|;)")
MODIFIER_RE = re.compile(r"\bmodifier\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
ACCESS_RE = re.compile(r"\b(onlyOwner|onlyRole|hasRole|requiresAuth|require\s*\(\s*msg\.sender|msg\.sender\s*==|isAuthorized|auth)", re.I)
ACCOUNTING_RE = re.compile(r"(\+=|-=|totalAssets|totalSupply|balance|shares?|reward|debt|accounting|deposit|withdraw|claim|mint|redeem)", re.I)
EXTERNAL_ORDER_RE = re.compile(r"(\.call\b|delegatecall|staticcall|safeTransfer|safeTransferFrom|transferFrom|transfer\s*\(|external call)", re.I)
REENTRANCY_RE = re.compile(r"(nonReentrant|reentran|callback|ERC777|onERC721Received|onERC1155Received)", re.I)
SIGNATURE_RE = re.compile(r"(ecrecover|ECDSA|signature|nonce|deadline|DOMAIN_SEPARATOR|chainId|permit|replay)", re.I)
ORACLE_RE = re.compile(r"(latestRoundData|oracle|price|TWAP|slot0|answeredInRound|updatedAt|stale)", re.I)
LOOP_RE = re.compile(r"(for\s*\(|while\s*\(|progress|cursor|index|processed|checkpoint)", re.I)
VALIDATION_RE = re.compile(r"(require\s*\(|revert\s+|if\s*\(|assert\s*\(|custom error)", re.I)


def load_manifest(root: Path) -> dict[str, Any]:
    path = root / "patched_control_manifest.json"
    if not path.exists():
        return {"pairs": []}
    return json.loads(path.read_text(errors="replace"))


def solidity_files(root: Path) -> dict[str, Path]:
    ignored = {"lib", "test", "tests", "script", "scripts", "node_modules", "broadcast", "cache", "out"}
    rows: dict[str, Path] = {}
    for p in sorted(root.rglob("*.sol")):
        if not p.is_file():
            continue
        rel = p.relative_to(root)
        if set(rel.parts).intersection(ignored):
            continue
        rows[rel.as_posix()] = p
    return rows


def extract_functions(text: str) -> set[str]:
    return set(FUNCTION_RE.findall(text))


def extract_modifiers(text: str) -> set[str]:
    return set(MODIFIER_RE.findall(text))


def classify_security_changes(diff_lines: list[str]) -> list[dict[str, Any]]:
    categories = [
        ("changed_access_controls", ACCESS_RE),
        ("changed_arithmetic_accounting_logic", ACCOUNTING_RE),
        ("changed_external_call_ordering", EXTERNAL_ORDER_RE),
        ("changed_reentrancy_protections", REENTRANCY_RE),
        ("changed_signature_nonce_domain_logic", SIGNATURE_RE),
        ("changed_oracle_price_checks", ORACLE_RE),
        ("changed_loop_progress_behavior", LOOP_RE),
        ("changed_validation_logic", VALIDATION_RE),
    ]
    rows = []
    changed_text = "\n".join(line for line in diff_lines if line.startswith(("+", "-")) and not line.startswith(("+++", "---")))
    for category, regex in categories:
        matches = sorted(set(regex.findall(changed_text)))
        if matches:
            rows.append({"category": category, "matched_tokens": [str(m) for m in matches[:12]]})
    return rows


def diff_pair_files(vulnerable_root: Path, patched_root: Path) -> tuple[list[dict[str, Any]], list[str], list[str], list[str]]:
    vuln_files = solidity_files(vulnerable_root)
    patched_files = solidity_files(patched_root)
    changed_rows: list[dict[str, Any]] = []
    changed_functions: set[str] = set()
    changed_modifiers: set[str] = set()
    all_diff_lines: list[str] = []
    common = set(vuln_files) & set(patched_files)
    rels = common or (set(vuln_files) | set(patched_files))
    for rel in sorted(rels):
        old = vuln_files.get(rel)
        new = patched_files.get(rel)
        old_text = old.read_text(errors="replace") if old else ""
        new_text = new.read_text(errors="replace") if new else ""
        if old_text == new_text:
            continue
        diff_lines = list(difflib.unified_diff(old_text.splitlines(), new_text.splitlines(), fromfile=f"vulnerable/{rel}", tofile=f"patched/{rel}", lineterm=""))
        all_diff_lines.extend(diff_lines)
        old_funcs = extract_functions(old_text)
        new_funcs = extract_functions(new_text)
        function_delta = sorted(old_funcs ^ new_funcs)
        if not function_delta and old_funcs.intersection(new_funcs):
            # Attribute content changes in a Solidity file to all shared functions
            # when a precise AST diff is unavailable.
            function_delta = sorted(old_funcs.intersection(new_funcs))
        modifier_delta = sorted(extract_modifiers(old_text) ^ extract_modifiers(new_text))
        changed_functions.update(function_delta)
        changed_modifiers.update(modifier_delta)
        changed_rows.append({
            "file": rel,
            "status": "added" if old is None else ("removed" if new is None else "modified"),
            "changed_functions": function_delta,
            "changed_modifiers": modifier_delta,
            "line_delta_count": sum(1 for line in diff_lines if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))),
        })
    return changed_rows, sorted(changed_functions), sorted(changed_modifiers), all_diff_lines


def require_frozen_pair(root: Path, pair: dict[str, Any]) -> tuple[bool, list[str]]:
    blocks = []
    for key in ["vulnerable_case_id", "patched_case_id"]:
        loaded = load_case_outputs(root, pair[key])
        if loaded["status"] != "PASS":
            blocks.append(f"{pair[key]} frozen outputs missing or invalid")
    return (not blocks, blocks)


def mechanism(security_changes: list[dict[str, Any]]) -> str:
    if not security_changes:
        return "no security-relevant patch mechanism inferred from source diff"
    preferred = security_changes[0]["category"].replace("changed_", "").replace("_", " ")
    return f"patch appears to change {preferred}"


def analyze_pair(root: Path, pair: dict[str, Any]) -> dict[str, Any]:
    frozen, blocks = require_frozen_pair(root, pair)
    if not frozen:
        return {"pair_id": pair.get("pair_id"), "status": "BLOCKED", "reason": "frozen outputs required before patch-diff analysis", "blocks": blocks, "report_ready_created": False}
    vulnerable_root = root / pair.get("vulnerable_detector_visible_path", f"patched-controls/{pair['vulnerable_case_id']}")
    patched_root = root / pair.get("patched_detector_visible_path", f"patched-controls/{pair['patched_case_id']}")
    changed_files, changed_functions, changed_modifiers, diff_lines = diff_pair_files(vulnerable_root, patched_root)
    security_changes = classify_security_changes(diff_lines)
    confidence = min(1.0, 0.15 * len(changed_files) + 0.15 * len(changed_functions) + 0.18 * len(security_changes))
    original_removed = bool(security_changes and confidence >= 0.3)
    return {
        "pair_id": pair["pair_id"],
        "status": "PASS",
        "changed_files": changed_files,
        "changed_functions": changed_functions,
        "changed_modifiers": changed_modifiers,
        "security_relevant_changes": security_changes,
        "suspected_patch_mechanism": mechanism(security_changes),
        "original_exploit_path_removed": original_removed,
        "patch_confidence": round(confidence, 2),
        "remaining_uncertainties": ["no executable regression PoC run", "diff heuristic is not a proof of exploitability"],
        "metadata_used_after_freeze_only": True,
        "report_ready_created": False,
        "counts_as_finding": False,
    }


def analyze_split(root: Path = PUBLIC_ROOT, *, split: str = "patched-controls") -> dict[str, Any]:
    manifest = load_manifest(root)
    pairs = manifest.get("pairs", [])
    rows = [analyze_pair(root, pair) for pair in pairs]
    result = {
        "status": "PASS" if rows and all(r["status"] == "PASS" for r in rows) else "BLOCKED",
        "split": split,
        "pair_count": len(rows),
        "patch_diff_explained_count": sum(1 for r in rows if r.get("original_exploit_path_removed")),
        "metadata_used_after_freeze_only": True,
        "report_ready_created": False,
        "pairs": rows,
    }
    out = root / "scoring" / "patch_diff_analysis.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Analyze vulnerable/patched source diffs after freeze")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="patched-controls")
    p.add_argument("--frozen-only", action="store_true")
    args = p.parse_args(argv)
    result = analyze_split(Path(args.root), split=args.split)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
