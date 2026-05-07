#!/usr/bin/env python3
"""Import Proof-of-Patch vulnerable/patched source pairs with metadata isolation."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from public_case_sanitizer import sanitize_ignore

PUBLIC_ROOT = Path(__file__).resolve().parents[1] / "benchmarks" / "public-historical-corpus"
RAW_POP = PUBLIC_ROOT / "sources" / "raw" / "patched-controls" / "proof_of_patch"
APPROVED_SUBMODULE_URLS = {
    "https://github.com/code-423n4/2024-06-size.git",
    "https://github.com/code-423n4/2023-07-pooltogether.git",
    "https://github.com/code-423n4/2023-09-centrifuge.git",
}
SOURCE_COPY_ALLOWLIST = [
    "src",
    "contracts",
    "lib",
    "foundry.toml",
    "remappings.txt",
    "hardhat.config.js",
    "hardhat.config.ts",
    "truffle-config.js",
]
FORBIDDEN_IMPORT_NAMES = {
    ".git",
    ".github",
    "audits",
    "audit_reports",
    "reports",
    "issues",
    "public_writeups",
    "expected_findings",
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


def load_metadata(raw_root: Path) -> dict[str, Any]:
    meta = raw_root / "dataset_metadata.json"
    if not meta.exists():
        return {}
    return json.loads(meta.read_text(errors="replace"))


def parse_gitmodules(raw_root: Path) -> dict[str, str]:
    """Parse local .gitmodules without fetching anything."""
    path = raw_root / ".gitmodules"
    if not path.exists():
        return {}
    rows: dict[str, dict[str, str]] = {}
    current = ""
    for raw_line in path.read_text(errors="replace").splitlines():
        line = raw_line.strip()
        if line.startswith("[submodule "):
            current = line.split('"', 2)[1] if '"' in line else line
            rows.setdefault(current, {})
            continue
        if not current or "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        if key in {"path", "url"}:
            rows.setdefault(current, {})[key] = value
    return {row["path"]: row["url"] for row in rows.values() if row.get("path") and row.get("url")}


def submodule_for_target(target_directory: str, submodules: dict[str, str]) -> tuple[str, str] | None:
    matches = [(path, url) for path, url in submodules.items() if target_directory == path or target_directory.startswith(path + "/")]
    if not matches:
        return None
    return max(matches, key=lambda item: len(item[0]))


def git_commit(path: Path) -> str:
    if not path.exists() or not (path / ".git").exists():
        return ""
    result = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], text=True, capture_output=True, timeout=30, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def license_note(path: Path) -> str:
    files = sorted(p.name for p in path.glob("LICENSE*") if p.is_file()) if path.exists() else []
    return "root license file present: " + ", ".join(files) if files else "license file not found at source root; verify manually"


def detector_ignore(directory: str, names: list[str]) -> set[str]:
    ignored = set(sanitize_ignore(directory, names))
    for name in names:
        lowered = name.lower()
        if lowered in FORBIDDEN_IMPORT_NAMES or lowered.startswith("readme") or lowered.startswith("bot-report"):
            ignored.add(name)
    return ignored


def is_allowed_fallback_sol(src: Path, sol: Path) -> bool:
    rel_parts = sol.relative_to(src).parts
    lowered = {part.lower() for part in rel_parts}
    return not lowered.intersection(FORBIDDEN_IMPORT_NAMES)


def has_solidity(path: Path) -> bool:
    return path.exists() and any(is_allowed_fallback_sol(path, sol) for sol in path.rglob("*.sol"))


def copy_detector_visible(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True, exist_ok=True)
    for rel in SOURCE_COPY_ALLOWLIST:
        s = src / rel
        if s.is_dir():
            shutil.copytree(s, dst / rel, ignore=detector_ignore)
        elif s.exists():
            shutil.copy2(s, dst / rel)
    if not any(dst.rglob("*.sol")):
        # Some Proof-of-Patch entries store a single file at project root.
        for sol in src.rglob("*.sol"):
            if not is_allowed_fallback_sol(src, sol):
                continue
            rel = sol.relative_to(src)
            (dst / rel.parent).mkdir(parents=True, exist_ok=True)
            shutil.copy2(sol, dst / rel)


def metadata_for_import(row: dict[str, Any]) -> dict[str, Any]:
    return {k: row.get(k) for k in ["finding_id", "repo_name", "code_repo", "main_contract", "target_directory", "patch", "patch_ref", "finding_link", "expected_vulnerability", "impact", "annotations", "poc_path", "poc_ref"]}


def approved_submodule_rows(raw_root: Path, submodules: dict[str, str]) -> list[dict[str, Any]]:
    rows = []
    for path, url in sorted(submodules.items()):
        if url not in APPROVED_SUBMODULE_URLS:
            continue
        full_path = raw_root / path
        commit = git_commit(full_path)
        rows.append({
            "source_url": url,
            "submodule_path": path,
            "exact_approved_url_match": True,
            "fetched": bool(commit),
            "commit_hash": commit,
            "license_note": license_note(full_path),
            "status": "FETCHED" if commit else "NOT_FETCHED",
        })
    return rows


def import_pairs(root: Path = PUBLIC_ROOT, *, raw_root: Path = RAW_POP, min_pairs: int = 3, approved_submodules_only: bool = False) -> dict[str, Any]:
    metadata = load_metadata(raw_root)
    if not metadata:
        return {"status": "BLOCKED", "reason": "Proof-of-Patch metadata not available", "proof_of_patch_pairs_attempted": 0, "proof_of_patch_pairs_imported": 0, "proof_of_patch_pairs_blocked": 0}
    submodules = parse_gitmodules(raw_root)
    approved_rows = approved_submodule_rows(raw_root, submodules)
    out_root = root / "patched-controls"
    meta_root = root / "patched-control-metadata"
    if out_root.exists():
        shutil.rmtree(out_root)
    out_root.mkdir(parents=True, exist_ok=True)
    meta_root.mkdir(parents=True, exist_ok=True)
    rows = []
    imported = []
    for finding_id in sorted(metadata):
        row = metadata[finding_id]
        candidate_id = f"pop_candidate_{int(finding_id):04d}"
        vuln_src = raw_root / str(row.get("target_directory", ""))
        patched_src = raw_root / str(row.get("patch", "")) / str(row.get("repo_name", ""))
        if not patched_src.exists():
            patched_src = raw_root / str(row.get("patch", ""))
        submodule = submodule_for_target(str(row.get("target_directory", "")), submodules)
        submodule_path, submodule_url = submodule if submodule else ("", "")
        submodule_commit = git_commit(raw_root / submodule_path) if submodule_path else ""
        reason = ""
        if approved_submodules_only and submodule_url not in APPROVED_SUBMODULE_URLS:
            reason = "unapproved submodule URL for vulnerable source"
        elif approved_submodules_only and not submodule_commit:
            reason = "approved submodule path not fetched"
        elif not has_solidity(vuln_src):
            reason = "vulnerable source directory unavailable or has no Solidity files"
            if (raw_root / submodule_path / ".gitmodules").exists():
                reason = "vulnerable source blocked_missing_nested_submodule_or_dependencies"
        elif not has_solidity(patched_src):
            reason = "patched source directory unavailable or has no Solidity files"
        if reason:
            rows.append({"pair_id": candidate_id, "finding_id": finding_id, "status": "BLOCKED", "reason": reason, "source_url": submodule_url, "submodule_path": submodule_path, "submodule_commit": submodule_commit, "metadata_used_for_import_only": True})
            continue
        pair_id = f"case_pc_{len(imported) + 1:04d}"
        vuln_case = f"{pair_id}_vulnerable"
        patched_case = f"{pair_id}_patched"
        copy_detector_visible(vuln_src, out_root / vuln_case)
        copy_detector_visible(patched_src, out_root / patched_case)
        metadata_payload = metadata_for_import(row) | {
            "pair_id": pair_id,
            "vulnerable_case_id": vuln_case,
            "patched_case_id": patched_case,
            "source_url": submodule_url,
            "submodule_path": submodule_path,
            "submodule_commit": submodule_commit,
            "license_note": license_note(raw_root / submodule_path) if submodule_path else "license file not found at source root; verify manually",
            "metadata_forbidden_during_detection": True,
            "metadata_layer": "import_metadata_layer_and_post_freeze_scoring_layer_only",
        }
        (meta_root / f"{pair_id}.json").write_text(json.dumps(metadata_payload, indent=2) + "\n")
        entry = {"pair_id": pair_id, "finding_id": finding_id, "source_url": submodule_url, "submodule_path": submodule_path, "submodule_commit": submodule_commit, "license_note": metadata_payload["license_note"], "vulnerable_case_id": vuln_case, "patched_case_id": patched_case, "vulnerable_detector_visible_path": f"patched-controls/{vuln_case}", "patched_detector_visible_path": f"patched-controls/{patched_case}", "metadata_path": f"patched-control-metadata/{pair_id}.json", "metadata_hidden_during_detection": True, "status": "IMPORTED"}
        rows.append(entry)
        imported.append(entry)
        if len(imported) >= min_pairs:
            break
    manifest = {"status": "PASS" if len(imported) >= min_pairs else "BLOCKED", "source": "ASSERT-KTH/Proof-of-Patch", "approved_submodules_only": approved_submodules_only, "approved_submodules": approved_rows, "submodule_urls_requested": sorted(APPROVED_SUBMODULE_URLS), "submodule_urls_approved": sorted(APPROVED_SUBMODULE_URLS), "submodule_urls_fetched": sorted({row["source_url"] for row in approved_rows if row.get("fetched")}), "unapproved_submodule_fetch_attempts": 0, "pairs": imported, "blocked": [r for r in rows if r.get("status") == "BLOCKED"], "proof_of_patch_pairs_attempted": len(rows), "proof_of_patch_pairs_imported": len(imported), "proof_of_patch_pairs_blocked": len([r for r in rows if r.get("status") == "BLOCKED"]), "vulnerable_source_present_count": sum(1 for p in imported if has_solidity(root / p["vulnerable_detector_visible_path"])), "patched_source_present_count": sum(1 for p in imported if has_solidity(root / p["patched_detector_visible_path"])), "metadata_hidden_during_detection": True, "metadata_rule": "metadata used only to locate pairs; detector-visible directories contain neutral source copies"}
    (root / "scoring" / "proof_of_patch_import.json").parent.mkdir(parents=True, exist_ok=True)
    (root / "scoring" / "proof_of_patch_import.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (root / "patched_control_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Import Proof-of-Patch pairs")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--raw-root", default=str(RAW_POP))
    p.add_argument("--approved-source", default="ASSERT-KTH/Proof-of-Patch")
    p.add_argument("--approved-submodules-only", action="store_true")
    p.add_argument("--min-pairs", type=int, default=3)
    args = p.parse_args(argv)
    if args.approved_source != "ASSERT-KTH/Proof-of-Patch":
        print(json.dumps({"status": "BLOCKED", "reason": "unapproved Proof-of-Patch source"}, indent=2))
        return 1
    result = import_pairs(Path(args.root), raw_root=Path(args.raw_root), min_pairs=args.min_pairs, approved_submodules_only=args.approved_submodules_only)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
