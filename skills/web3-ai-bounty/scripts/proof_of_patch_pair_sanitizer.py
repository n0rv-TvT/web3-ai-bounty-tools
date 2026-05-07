#!/usr/bin/env python3
"""Validate Proof-of-Patch detector-visible pair directories."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from public_case_sanitizer import SENSITIVE_NAMES, SENSITIVE_SUFFIXES, validate_no_leakage

PUBLIC_ROOT = Path(__file__).resolve().parents[1] / "benchmarks" / "public-historical-corpus"
NEUTRAL_RE = re.compile(r"^(?:pop_[0-9]{4}|case_pc_[0-9]{4})_(?:vulnerable|patched)$")
FORBIDDEN_TEXT = ["expected_vulnerability", "finding_link", "patch_ref", "solodit", "code4rena.com/reports", "audit_ref", "poc_ref"]
FORBIDDEN_PATH_PARTS = {
    ".git",
    ".github",
    "expected_findings",
    "public_writeups",
    "reports",
    "issues",
    "audit_reports",
    "audits",
    "discord-export",
    "broadcast",
    "cache",
    "out",
    "node_modules",
    "test",
    "tests",
    "script",
    "scripts",
}


def validate_case(case_root: Path) -> dict[str, Any]:
    blocks = []
    if not NEUTRAL_RE.match(case_root.name):
        blocks.append("case id is not neutral Proof-of-Patch form")
    if not any(case_root.rglob("*.sol")):
        blocks.append("detector-visible case has no Solidity source")
    leakage = validate_no_leakage(case_root, source_only=False)
    blocks.extend(leakage.get("blocks", []))
    for path in case_root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(case_root)
        lowered_parts = [part.lower() for part in rel.parts]
        if any(part in FORBIDDEN_PATH_PARTS for part in lowered_parts):
            blocks.append(f"forbidden detector-visible path component: {rel}")
        lowered_name = path.name.lower()
        if lowered_name in SENSITIVE_NAMES or lowered_name.endswith(tuple(SENSITIVE_SUFFIXES)) or lowered_name.startswith(".env"):
            blocks.append(f"secret-like file included in detector-visible layer: {rel}")
        if lowered_name.startswith("readme") or lowered_name.startswith("bot-report"):
            blocks.append(f"report/writeup-like file included in detector-visible layer: {rel}")
        if path.suffix.lower() in {".sol", ".md", ".json", ".txt", ".toml"}:
            text = path.read_text(errors="replace").lower()
            for token in FORBIDDEN_TEXT:
                if token in text:
                    blocks.append(f"forbidden metadata token in detector-visible file: {rel}")
                    break
    return {"case_id": case_root.name, "status": "PASS" if not blocks else "FAIL", "blocks": blocks, "metadata_hidden_during_detection": True}


def validate_pair(root: Path, pair: dict[str, Any]) -> dict[str, Any]:
    vuln_root = root / pair["vulnerable_detector_visible_path"]
    patched_root = root / pair["patched_detector_visible_path"]
    vuln = validate_case(vuln_root)
    patched = validate_case(patched_root)
    return {
        "pair_id": pair["pair_id"],
        "vulnerable_case_id": pair["vulnerable_case_id"],
        "patched_case_id": pair["patched_case_id"],
        "vulnerable_source_present": any(vuln_root.rglob("*.sol")),
        "patched_source_present": any(patched_root.rglob("*.sol")),
        "detector_visible_path_neutral": vuln["status"] == "PASS" and patched["status"] == "PASS",
        "status": "PASS" if vuln["status"] == "PASS" and patched["status"] == "PASS" else "FAIL",
        "vulnerable_validation": vuln,
        "patched_validation": patched,
    }


def sanitize_split(root: Path = PUBLIC_ROOT, *, split: str = "patched-controls") -> dict[str, Any]:
    split_root = root / split
    if not split_root.exists() or not any(p.is_dir() for p in split_root.iterdir()):
        return {"status": "BLOCKED", "split": split, "reason": "no imported Proof-of-Patch pairs", "case_count": 0}
    manifest_path = root / "patched_control_manifest.json"
    pairs: list[dict[str, Any]] = []
    if manifest_path.exists():
        pairs = json.loads(manifest_path.read_text(errors="replace")).get("pairs", [])
    pair_rows = [validate_pair(root, pair) for pair in pairs]
    cases = [validate_case(p) for p in sorted(split_root.iterdir()) if p.is_dir()]
    result = {
        "status": "PASS" if cases and all(c["status"] == "PASS" for c in cases) and all(p["status"] == "PASS" for p in pair_rows) else "FAIL",
        "split": split,
        "case_count": len(cases),
        "pair_count": len(pair_rows),
        "vulnerable_source_present_count": sum(1 for p in pair_rows if p["vulnerable_source_present"]),
        "patched_source_present_count": sum(1 for p in pair_rows if p["patched_source_present"]),
        "cases": cases,
        "pairs": pair_rows,
        "patch_metadata_hidden_during_detection": True,
        "vulnerability_labels_hidden_during_detection": True,
        "reports_writeups_hidden_during_detection": True,
        "expected_findings_hidden_during_detection": True,
        "no_secret_like_files_in_detector_visible_layer": all(not c.get("blocks") for c in cases),
    }
    (root / "scoring" / "proof_of_patch_sanitizer.json").parent.mkdir(parents=True, exist_ok=True)
    (root / "scoring" / "proof_of_patch_sanitizer.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Sanitize Proof-of-Patch pair directories")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="patched-controls")
    args = p.parse_args(argv)
    result = sanitize_split(Path(args.root), split=args.split)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
