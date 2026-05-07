#!/usr/bin/env python3
"""Lightweight Solidity entry point scanner for Web3 x-ray prep.

This is intentionally conservative. It extracts candidates and useful facts; it
does not prove vulnerabilities. Always verify important classifications manually.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


EXCLUDE_DIRS = {".git", "node_modules", "lib", "out", "cache", "artifacts", "broadcast"}
TEST_PATTERNS = (".t.sol", "Test.sol", "Mock.sol")
ACCESS_MODIFIERS = {"nonReentrant", "whenNotPaused", "whenPaused", "payable", "virtual", "override"}


@dataclass
class EntryPoint:
    file: str
    line: int
    contract: str
    name: str
    visibility: str
    access: str
    modifiers: list[str]
    inline_sender_checks: list[str]
    parameters: str
    value_flow: str
    writes: list[str]
    external_calls: list[str]
    reentrancy_guard: bool
    payable: bool


def strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), src, flags=re.S)
    src = re.sub(r"//.*", "", src)
    return src


def iter_sol_files(root: Path, src_dir: str | None, include_tests: bool) -> Iterable[Path]:
    base = root / src_dir if src_dir else root
    if not base.exists():
        base = root
    for path in base.rglob("*.sol"):
        parts = set(path.parts)
        if parts & EXCLUDE_DIRS:
            continue
        if "interfaces" in parts or "interface" in parts:
            continue
        if not include_tests and any(str(path).endswith(p) for p in TEST_PATTERNS):
            continue
        if not include_tests and any(part.lower() in {"test", "tests", "mock", "mocks"} for part in path.parts):
            continue
        yield path


def line_no(src: str, idx: int) -> int:
    return src.count("\n", 0, idx) + 1


def find_contract_at(src: str, idx: int) -> str:
    prefix = src[:idx]
    matches = list(re.finditer(r"\b(contract|abstract\s+contract|library)\s+([A-Za-z_][A-Za-z0-9_]*)", prefix))
    return matches[-1].group(2) if matches else "<unknown>"


def find_matching(src: str, start: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    i = start
    while i < len(src):
        ch = src[i]
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def extract_function_body(src: str, brace_idx: int) -> tuple[str, int]:
    end = find_matching(src, brace_idx, "{", "}")
    if end == -1:
        return "", brace_idx
    return src[brace_idx + 1 : end], end


def parse_params(sig: str) -> str:
    m = re.search(r"function\s+[A-Za-z_][A-Za-z0-9_]*\s*\((.*)\)", sig, flags=re.S)
    if not m:
        return ""
    return " ".join(m.group(1).split())


def parse_modifiers(sig_tail: str) -> list[str]:
    tail = re.sub(r"returns\s*\([^)]*\)", " ", sig_tail, flags=re.S)
    tail = re.sub(r"\b(external|public|internal|private|view|pure|payable|virtual|override)\b", " ", tail)
    mods: list[str] = []
    for token in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\b(?:\s*\([^)]*\))?", tail):
        name = token.group(1)
        if name not in {"returns"}:
            mods.append(name)
    return mods


def classify_access(name: str, modifiers: list[str], body: str) -> tuple[str, list[str]]:
    sender_checks = []
    sender_guard = r"msg\.sender\s*(?:==|!=)|(?:==|!=)\s*msg\.sender"
    for m in re.finditer(r"(require\s*\([^;]*(?:" + sender_guard + r")[^;]*;|if\s*\([^)]*(?:" + sender_guard + r")[^)]*\)\s*(?:revert|throw|\{?\s*revert)[^;]*;)", body, flags=re.S):
        sender_checks.append(" ".join(m.group(1).split())[:220])

    low_mods = [m.lower() for m in modifiers]
    if name.lower() in {"initialize", "init"} or any("initializer" in m for m in low_mods):
        return "initializer", sender_checks
    if any(m in {"onlyowner", "onlyadmin"} or "default_admin" in m or m.endswith("admin") for m in low_mods):
        return "admin-only", sender_checks
    if any(m.startswith("only") or "role" in m for m in low_mods) or sender_checks:
        return "role-gated", sender_checks
    effective_mods = [m for m in modifiers if m not in ACCESS_MODIFIERS]
    if effective_mods:
        return "role-gated?", sender_checks
    return "permissionless", sender_checks


def extract_writes(body: str) -> list[str]:
    writes = set()
    patterns = [
        r"\b([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])?)\s*(?:\+\+|--)",
        r"\b([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])?)\s*(?:\+=|-=|\*=|/=|%=|=)",
    ]
    skip = {"if", "for", "while", "return", "require", "assert", "revert", "emit"}
    for pat in patterns:
        for m in re.finditer(pat, body):
            name = m.group(1).split("[")[0]
            if name not in skip and not name[0].isupper():
                writes.add(m.group(1))
    return sorted(writes)[:40]


def extract_external_calls(body: str) -> list[str]:
    calls = set()
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", body):
        obj, fn = m.group(1), m.group(2)
        if obj not in {"super", "this", "vm", "console", "console2"}:
            calls.add(f"{obj}.{fn}()")
    return sorted(calls)[:40]


def value_flow(body: str, payable: bool) -> str:
    incoming = bool(re.search(r"transferFrom\s*\(|msg\.value", body)) or payable
    outgoing = bool(re.search(r"\.\s*(transfer|safeTransfer|call)\s*(?:\{|\()", body))
    if incoming and outgoing:
        return "both"
    if incoming:
        return "in"
    if outgoing:
        return "out"
    return "none"


def scan_file(path: Path, root: Path, include_view: bool) -> list[EntryPoint]:
    raw = path.read_text(errors="replace")
    src = strip_comments(raw)
    entries: list[EntryPoint] = []
    for m in re.finditer(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", src):
        name = m.group(1)
        paren = src.find("(", m.start())
        close = find_matching(src, paren, "(", ")")
        if close == -1:
            continue
        cursor = close + 1
        while cursor < len(src) and src[cursor].isspace():
            cursor += 1
        end_sig = cursor
        while end_sig < len(src) and src[end_sig] not in "{;":
            end_sig += 1
        if end_sig >= len(src) or src[end_sig] == ";":
            continue
        sig = src[m.start() : end_sig]
        vis = re.search(r"\b(external|public|internal|private)\b", sig)
        if not vis or vis.group(1) not in {"external", "public"}:
            continue
        if not include_view and re.search(r"\b(view|pure)\b", sig):
            continue
        params = parse_params(sig)
        modifiers = parse_modifiers(sig[close - m.start() + 1 :])
        body, _ = extract_function_body(src, end_sig)
        access, sender_checks = classify_access(name, modifiers, body)
        calls = extract_external_calls(body)
        payable = bool(re.search(r"\bpayable\b", sig))
        entries.append(
            EntryPoint(
                file=str(path.relative_to(root)),
                line=line_no(src, m.start()),
                contract=find_contract_at(src, m.start()),
                name=name,
                visibility=vis.group(1),
                access=access,
                modifiers=modifiers,
                inline_sender_checks=sender_checks,
                parameters=params,
                value_flow=value_flow(body, payable),
                writes=extract_writes(body),
                external_calls=calls,
                reentrancy_guard="nonReentrant" in modifiers,
                payable=payable,
            )
        )
    return entries


def print_markdown(entries: list[EntryPoint]) -> None:
    print("# Entry Point Scan")
    print()
    print(f"Total entry points: {len(entries)}")
    print()
    by_access: dict[str, int] = {}
    for e in entries:
        by_access[e.access] = by_access.get(e.access, 0) + 1
    for k in sorted(by_access):
        print(f"- {k}: {by_access[k]}")
    print()
    print("| File:Line | Contract.function | Access | Mods | Flow | Writes | External calls |")
    print("|---|---|---|---|---|---|---|")
    for e in entries:
        mods = ", ".join(e.modifiers) or "-"
        writes = ", ".join(e.writes[:8]) or "-"
        calls = ", ".join(e.external_calls[:8]) or "-"
        print(f"| {e.file}:{e.line} | `{e.contract}.{e.name}` | {e.access} | {mods} | {e.value_flow} | {writes} | {calls} |")


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan Solidity public/external entry points")
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--src-dir", default=None)
    ap.add_argument("--include-tests", action="store_true")
    ap.add_argument("--include-view", action="store_true")
    ap.add_argument("--json", dest="json_path")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    entries: list[EntryPoint] = []
    for path in iter_sol_files(root, args.src_dir, args.include_tests):
        entries.extend(scan_file(path, root, args.include_view))
    entries.sort(key=lambda e: (e.file, e.line))

    if args.json_path:
        Path(args.json_path).write_text(json.dumps([asdict(e) for e in entries], indent=2))
    print_markdown(entries)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
