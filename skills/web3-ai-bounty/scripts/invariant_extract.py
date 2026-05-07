#!/usr/bin/env python3
"""Extract guard/write-site facts for invariant-led Web3 hunting."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path


EXCLUDE = {".git", "node_modules", "lib", "out", "cache", "artifacts", "test", "tests", "mocks"}


@dataclass
class Guard:
    file: str
    line: int
    predicate: str
    storage_terms: list[str]


@dataclass
class WriteSite:
    file: str
    line: int
    variable: str
    op: str
    snippet: str


def strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), src, flags=re.S)
    return re.sub(r"//.*", "", src)


def sol_files(root: Path):
    for p in root.rglob("*.sol"):
        if any(part in EXCLUDE for part in p.parts):
            continue
        if str(p).endswith(".t.sol") or "Test" in p.name or "Exploit" in p.name:
            continue
        if "interfaces" in p.parts:
            continue
        yield p


def line_no(src: str, idx: int) -> int:
    return src.count("\n", 0, idx) + 1


def extract_terms(expr: str) -> list[str]:
    terms = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", expr))
    skip = {
        "require", "assert", "revert", "if", "else", "true", "false", "address", "uint256",
        "uint128", "uint64", "uint32", "uint16", "uint8", "int256", "msg", "sender", "value",
        "block", "timestamp", "number", "this", "super", "memory", "storage", "calldata",
    }
    return sorted(t for t in terms if t not in skip and not t[0].isupper())


def scan(root: Path):
    guards: list[Guard] = []
    writes: list[WriteSite] = []
    for path in sol_files(root):
        raw = path.read_text(errors="replace")
        src = strip_comments(raw)
        rel = str(path.relative_to(root))
        for m in re.finditer(r"(require\s*\((.*?)\)\s*;|assert\s*\((.*?)\)\s*;|if\s*\((.*?)\)\s*revert[^;]*;)", src, flags=re.S):
            pred = " ".join(m.group(0).split())
            terms = extract_terms(pred)
            if terms:
                guards.append(Guard(rel, line_no(src, m.start()), pred[:260], terms[:20]))
        for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])?)\s*(\+\+|--|\+=|-=|\*=|/=|%=|=)", src):
            var = m.group(1).split("[")[0]
            snippet = src[m.start() : src.find(";", m.start()) + 1]
            if "=>" in snippet or "mapping(" in snippet:
                continue
            if var in {"i", "j", "k", "amount", "shares", "assets", "success", "address"}:
                continue
            if len(snippet) > 220:
                snippet = snippet[:220]
            writes.append(WriteSite(rel, line_no(src, m.start()), var, m.group(2), " ".join(snippet.split())))
    return guards, writes


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract guards and write sites")
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--json", dest="json_path")
    args = ap.parse_args()
    root = Path(args.root).resolve()
    guards, writes = scan(root)
    writes_by_var: defaultdict[str, list[WriteSite]] = defaultdict(list)
    guards_by_term: defaultdict[str, list[Guard]] = defaultdict(list)
    for w in writes:
        writes_by_var[w.variable].append(w)
    for g in guards:
        for t in g.storage_terms:
            guards_by_term[t].append(g)
    data = {
        "guards": [asdict(g) for g in guards],
        "writes": [asdict(w) for w in writes],
        "variables_with_multiple_writers": {k: [asdict(w) for w in v] for k, v in writes_by_var.items() if len(v) >= 2},
    }
    if args.json_path:
        Path(args.json_path).write_text(json.dumps(data, indent=2))

    print("# Invariant Extraction")
    print()
    print(f"Guards with persistent terms: {len(guards)}")
    print(f"Write sites: {len(writes)}")
    print()
    print("## Variables With Multiple Writers")
    for var, sites in sorted(writes_by_var.items(), key=lambda kv: len(kv[1]), reverse=True)[:40]:
        if len(sites) < 2:
            continue
        guarded = len(guards_by_term.get(var, []))
        print(f"- `{var}`: {len(sites)} writes, {guarded} guards mention it")
        for w in sites[:5]:
            print(f"  - {w.file}:{w.line} `{w.snippet}`")
    print()
    print("Turn variables with multiple writers and uneven guards into assumption/invariant leads.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
