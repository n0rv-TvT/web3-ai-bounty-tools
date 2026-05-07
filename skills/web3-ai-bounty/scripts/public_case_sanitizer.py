#!/usr/bin/env python3
"""Sanitize public historical benchmark cases to prevent leakage."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any


PUBLIC_CORPUS_ROOT = Path(__file__).resolve().parents[1] / "benchmarks" / "public-historical-corpus"
BUG_TOKENS = {
    "reentrancy", "oracle", "erc4626", "inflation", "reward", "signature", "replay", "proxy",
    "access", "control", "decimal", "rounding", "bridge", "mev", "liquidation", "storage", "collision",
}
FORBIDDEN_VISIBLE_DIRS = {"expected_findings", "public_writeups", "reports", "issues", "audit_reports", "automated_findings"}
NON_SOURCE_DIRS = {".git", "node_modules", "cache", "out", "broadcast"}
FORBIDDEN_SOURCE_MARKERS = ("<yes>", "<report>", "@vulnerable_at_lines", "vulnerable_at_lines")
SENSITIVE_NAMES = {
    ".env", ".env.local", ".env.production", ".env.development", "credentials.json",
    "secrets.json", "secret.json", "mnemonic.txt", "private_key.txt", "privatekey.txt",
}
SENSITIVE_SUFFIXES = {".key", ".pem", ".p12", ".pfx", ".keystore"}
DOCUMENTATION_SUFFIXES = {".md", ".txt", ".pdf", ".html", ".htm"}


def sha256_tree(root: Path) -> str:
    h = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        h.update(rel.encode())
        h.update(path.read_bytes())
    return h.hexdigest()


def neutral_case_id(index: int) -> str:
    return f"case_{index:04d}"


def case_name_leaks(case_id: str) -> bool:
    lowered = case_id.lower().replace("-", "_")
    parts = set(lowered.split("_")) | {lowered}
    return bool(parts.intersection(BUG_TOKENS))


def detector_visible_paths(case_root: Path) -> list[str]:
    if not case_root.exists():
        return []
    return [p.relative_to(case_root).as_posix() for p in case_root.rglob("*") if p.is_file()]


def validate_no_leakage(case_root: Path, *, source_only: bool = True) -> dict[str, Any]:
    blocks: list[str] = []
    if case_name_leaks(case_root.name):
        blocks.append(f"case directory leaks bug class: {case_root.name}")
    for rel in detector_visible_paths(case_root):
        first = rel.split("/", 1)[0]
        if first in FORBIDDEN_VISIBLE_DIRS:
            blocks.append(f"forbidden detector-visible path: {rel}")
        if source_only and (rel == "README.md" or rel.startswith("test/")):
            blocks.append(f"source-only forbidden path present in detector view: {rel}")
        path = case_root / rel
        if path.suffix in {".sol", ".js", ".ts", ".md", ".txt"}:
            lowered = path.read_text(errors="replace").lower()
            for marker in FORBIDDEN_SOURCE_MARKERS:
                if marker in lowered:
                    blocks.append(f"forbidden source-label marker in detector-visible file: {rel}")
                    break
    return {"status": "PASS" if not blocks else "FAIL", "blocks": blocks, "case_root": str(case_root)}


def sanitize_ignore(_dir: str, names: list[str]) -> set[str]:
    ignored: set[str] = set()
    for name in names:
        lowered = name.lower()
        if lowered in SENSITIVE_NAMES or lowered.endswith(tuple(SENSITIVE_SUFFIXES)) or lowered.endswith(tuple(DOCUMENTATION_SUFFIXES)) or lowered in FORBIDDEN_VISIBLE_DIRS or lowered in NON_SOURCE_DIRS:
            ignored.add(name)
    return ignored


def solidity_file_count(root: Path) -> int:
    if not root.exists():
        return 0
    return sum(1 for path in root.rglob("*.sol") if path.is_file())


def copy_if_present(source: Path, destination: Path) -> None:
    if source.is_dir():
        shutil.copytree(source, destination, ignore=sanitize_ignore, dirs_exist_ok=True)
    elif source.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def copy_nested_source_roots(imported_root: Path, output_root: Path) -> None:
    """Preserve Solidity source from multi-package repos without exposing reports."""
    for child in sorted(p for p in imported_root.iterdir() if p.is_dir()):
        lowered = child.name.lower()
        if lowered.startswith(".") or lowered in FORBIDDEN_VISIBLE_DIRS or lowered in NON_SOURCE_DIRS:
            continue
        for rel in ["src", "contracts"]:
            copy_if_present(child / rel, output_root / child.name / rel)
        for rel in ["foundry.toml", "hardhat.config.js", "truffle-config.js"]:
            copy_if_present(child / rel, output_root / child.name / rel)


def sanitize_case(imported_root: Path, output_root: Path, *, case_id: str) -> dict[str, Any]:
    if case_name_leaks(case_id):
        raise SystemExit(f"neutral case_id required, got {case_id}")
    if output_root.exists():
        shutil.rmtree(output_root)
    output_root.mkdir(parents=True, exist_ok=True)
    for rel in ["src", "contracts", "test", "foundry.toml", "hardhat.config.js", "truffle-config.js"]:
        copy_if_present(imported_root / rel, output_root / rel)
    raw_solidity_files = solidity_file_count(imported_root)
    detector_visible_solidity_files = solidity_file_count(output_root)
    if raw_solidity_files and detector_visible_solidity_files == 0:
        copy_nested_source_roots(imported_root, output_root)
        detector_visible_solidity_files = solidity_file_count(output_root)
    integrity_status = "PASS" if raw_solidity_files == 0 or detector_visible_solidity_files > 0 else "FAIL"
    mapping = {
        "case_id": case_id,
        "original_root": str(imported_root),
        "sanitized_root": str(output_root),
        "sanitized_hash": sha256_tree(output_root),
        "raw_solidity_file_count": raw_solidity_files,
        "detector_visible_solidity_file_count": detector_visible_solidity_files,
        "integrity_status": integrity_status,
    }
    return mapping


def sanitize_manifest(root: Path = PUBLIC_CORPUS_ROOT) -> dict[str, Any]:
    manifest_path = root / "corpus_manifest.json"
    if not manifest_path.exists():
        return {"status": "BLOCKED", "reason": "missing public corpus manifest", "sanitized_count": 0}
    manifest = json.loads(manifest_path.read_text(errors="replace"))
    blocks = []
    for case in manifest.get("cases", []):
        if case_name_leaks(str(case.get("case_id", ""))):
            blocks.append(f"case id leaks bug class: {case.get('case_id')}")
        visible_fields = [str(case.get("case_id", "")), str(case.get("source_name", "")), str(case.get("protocol_type", ""))]
        for value in visible_fields[:2]:
            tokens = set(re.split(r"[^a-z0-9]+", value.lower()))
            if tokens.intersection(BUG_TOKENS):
                blocks.append(f"visible manifest field leaks bug token: {value}")
        split = "holdout" if case.get("is_holdout") else ("patched" if case.get("is_patched_control") else "vulnerable")
        leakage = validate_no_leakage(root / split / str(case.get("case_id", "")), source_only=False)
        blocks.extend(leakage.get("blocks", []))
    return {"status": "PASS" if not blocks else "FAIL", "blocks": blocks, "sanitized_count": len(manifest.get("cases", []))}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Sanitize public historical benchmark corpus")
    p.add_argument("--root", default=str(PUBLIC_CORPUS_ROOT))
    args = p.parse_args(argv)
    result = sanitize_manifest(Path(args.root))
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
