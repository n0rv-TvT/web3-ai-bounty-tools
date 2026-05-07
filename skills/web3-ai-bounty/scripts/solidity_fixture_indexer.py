#!/usr/bin/env python3
"""Blind Solidity fixture indexer.

Indexes only Solidity source/test files requested by the caller. It does not read
expected_findings/, expected_results/, README files, or benchmark metadata.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SAFE_CONFIG_NAMES = {"foundry.toml", "remappings.txt"}
EXCLUDED_PARTS = {"expected_findings", "expected_results", "out", "cache", "broadcast", "script", "node_modules", "lib"}


def safe_rel(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def iter_solidity_files(root: Path, *, include_tests: bool = False, include_safe_config: bool = True) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*.sol")):
        rel_parts = set(path.resolve().relative_to(root.resolve()).parts)
        if rel_parts.intersection(EXCLUDED_PARTS):
            continue
        if not include_tests and "test" in rel_parts:
            continue
        files.append(path)
    if include_safe_config:
        for name in SAFE_CONFIG_NAMES:
            cfg = root / name
            if cfg.exists():
                files.append(cfg)
    return files


def line_offsets(text: str) -> list[int]:
    offsets = [0]
    for match in re.finditer("\n", text):
        offsets.append(match.end())
    return offsets


def line_for_offset(offsets: list[int], offset: int) -> int:
    line = 1
    for idx, start in enumerate(offsets, start=1):
        if start > offset:
            break
        line = idx
    return line


def find_matching_brace(text: str, open_index: int) -> int:
    depth = 0
    for idx in range(open_index, len(text)):
        char = text[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return idx
    return len(text) - 1


def mask_comments(text: str) -> str:
    """Replace comments with spaces while preserving length and newlines."""
    def repl(match: re.Match[str]) -> str:
        return "".join("\n" if ch == "\n" else " " for ch in match.group(0))
    text = re.sub(r"/\*.*?\*/", repl, text, flags=re.S)
    text = re.sub(r"//[^\n]*", repl, text)
    return text


def parse_functions(text: str, offsets: list[int], contract_start: int, contract_end: int) -> list[dict[str, Any]]:
    masked = mask_comments(text)
    body = masked[contract_start:contract_end]
    rows: list[dict[str, Any]] = []
    pattern = re.compile(r"\b(function|constructor)\s*([A-Za-z_][A-Za-z0-9_]*)?\s*\([^;{}]*\)\s*([^;{}]*)\{", re.S)
    for match in pattern.finditer(body):
        absolute_start = contract_start + match.start()
        open_brace = contract_start + match.end() - 1
        end = find_matching_brace(masked, open_brace)
        signature = text[absolute_start:open_brace].strip()
        fn_body = text[open_brace + 1:end]
        name = match.group(2) or "constructor"
        tail = match.group(3) or ""
        visibility = next((v for v in ["external", "public", "internal", "private"] if re.search(rf"\b{v}\b", tail)), "")
        modifiers = [m for m in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", tail) if m not in {visibility, "payable", "view", "pure", "virtual", "override", "returns", "memory", "calldata"}]
        rows.append({
            "name": name,
            "visibility": visibility,
            "modifiers": modifiers,
            "signature": signature,
            "body": fn_body,
            "start_line": line_for_offset(offsets, absolute_start),
            "end_line": line_for_offset(offsets, end),
        })
    return rows


def parse_contracts(text: str) -> list[dict[str, Any]]:
    offsets = line_offsets(text)
    masked = mask_comments(text)
    rows: list[dict[str, Any]] = []
    pattern = re.compile(r"\b(contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)([^{};]*)\{", re.S)
    for match in pattern.finditer(masked):
        open_brace = match.end() - 1
        end = find_matching_brace(masked, open_brace)
        body = text[open_brace + 1:end]
        rows.append({
            "kind": match.group(1),
            "name": match.group(2),
            "inherits": [x.strip().split()[0] for x in re.sub(r"\bis\b", "", match.group(3)).split(",") if x.strip()],
            "body": body,
            "start_line": line_for_offset(offsets, match.start()),
            "end_line": line_for_offset(offsets, end),
            "functions": parse_functions(text, offsets, open_brace + 1, end),
        })
    return rows


def index_project(root: Path, *, include_tests: bool = False) -> dict[str, Any]:
    read_files: list[str] = []
    files = []
    for path in iter_solidity_files(root, include_tests=include_tests):
        rel = safe_rel(path, root)
        if path.suffix != ".sol":
            read_files.append(rel)
            files.append({"path": rel, "kind": "safe_config", "contracts": [], "text": path.read_text(errors="replace")})
            continue
        text = path.read_text(errors="replace")
        read_files.append(rel)
        files.append({"path": rel, "kind": "solidity", "contracts": parse_contracts(text), "text": text})
    return {"project_root": str(root), "include_tests": include_tests, "read_files": read_files, "files": files}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Index Solidity benchmark source without answer keys")
    p.add_argument("project_root")
    p.add_argument("--include-tests", action="store_true")
    args = p.parse_args(argv)
    print(json.dumps(index_project(Path(args.project_root), include_tests=args.include_tests), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
