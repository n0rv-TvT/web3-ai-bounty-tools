#!/usr/bin/env python3
"""Runner for public historical benchmark modes."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from artifact_hasher import freeze_report, verify_frozen_report
from blind_source_analyzer import analyze_project
from public_adjudication_packet import generate_packets
from public_answer_key_guard import validate_detection_read_set
from public_benchmark_scoring import score_public_benchmark, zero_metrics
from public_case_build_runner import run_local_test
from public_case_manifest_validator import validate_public_manifest
from public_case_sanitizer import sanitize_manifest
from public_corpus_importer import PUBLIC_ROOT, ensure_public_corpus, import_public_corpus
from public_corpus_importer import detector_project_root
from public_case_sanitizer import sanitize_case, validate_no_leakage
from source_to_lead_converter import convert_analysis


MODES = {"import", "sanitize", "source-only", "source-plus-tests", "patched-controls", "holdout", "freeze", "score-only", "adjudication-packets"}
FRESH_SPLIT = "fresh-holdout"
FRESH_CONFIRMATION_SPLIT = "fresh-confirmation"
FRESH_V6_SPLIT = "fresh-v6"
FRESH_V8_SPLIT = "fresh-v8"
FRESH_SPLITS = {FRESH_SPLIT, FRESH_CONFIRMATION_SPLIT, FRESH_V6_SPLIT, FRESH_V8_SPLIT}
PATCHED_SPLIT = "patched-controls"
APPROVED_FRESH_URLS_BY_SPLIT = {
    FRESH_SPLIT: {
        "https://github.com/code-423n4/2024-07-basin",
        "https://github.com/code-423n4/2024-04-panoptic",
        "https://github.com/code-423n4/2024-04-renzo",
    },
    FRESH_CONFIRMATION_SPLIT: {
        "https://github.com/code-423n4/2025-10-sequence",
        "https://github.com/code-423n4/2025-11-ekubo",
        "https://github.com/code-423n4/2025-08-morpheus",
        "https://github.com/code-423n4/2025-04-bitvault",
        "https://github.com/code-423n4/2025-01-next-generation",
    },
    FRESH_V6_SPLIT: {
        "https://github.com/code-423n4/2025-11-brix-money",
        "https://github.com/code-423n4/2025-11-merkl",
        "https://github.com/code-423n4/2025-11-megapot",
        "https://github.com/code-423n4/2026-03-intuition",
    },
    FRESH_V8_SPLIT: {
        "https://github.com/code-423n4/2025-10-hybra-finance",
        "https://github.com/liquid-labs-inc/gte-contracts",
        "https://github.com/code-423n4/2025-04-kinetiq",
        "https://github.com/code-423n4/2025-04-virtuals-protocol",
    },
}
APPROVED_FRESH_CASE_IDS_BY_SPLIT = {
    FRESH_SPLIT: {"contest_2001", "contest_2002", "contest_2003"},
    FRESH_CONFIRMATION_SPLIT: {"contest_3001", "contest_3002", "contest_3003", "contest_3004_fallback", "contest_3005_fallback"},
    FRESH_V6_SPLIT: {"contest_4001", "contest_4002", "contest_4003", "contest_4004_fallback"},
    FRESH_V8_SPLIT: {"contest_5001", "contest_5002", "contest_5003", "contest_5004_fallback"},
}
PRIMARY_FRESH_CONFIRMATION_CASE_IDS = {"contest_3001", "contest_3002", "contest_3003"}
PRIMARY_FRESH_V6_CASE_IDS = {"contest_4001", "contest_4002", "contest_4003"}
PRIMARY_FRESH_V8_CASE_IDS = {"contest_5001", "contest_5002", "contest_5003"}
PRIMARY_FRESH_CASE_IDS_BY_SPLIT = {
    FRESH_SPLIT: APPROVED_FRESH_CASE_IDS_BY_SPLIT[FRESH_SPLIT],
    FRESH_CONFIRMATION_SPLIT: PRIMARY_FRESH_CONFIRMATION_CASE_IDS,
    FRESH_V6_SPLIT: PRIMARY_FRESH_V6_CASE_IDS,
    FRESH_V8_SPLIT: PRIMARY_FRESH_V8_CASE_IDS,
}
FRESH_SOURCE_MANIFESTS_BY_SPLIT = {
    FRESH_SPLIT: ["approved_fresh_holdout_sources.json", "fresh_holdout_sources.json"],
    FRESH_CONFIRMATION_SPLIT: ["approved_fresh_confirmation_holdouts.json", "approved_fresh_confirmation_sources.json"],
    FRESH_V6_SPLIT: ["approved_fresh_v6_holdouts.json", "approved_fresh_v6_sources.json"],
    FRESH_V8_SPLIT: ["approved_fresh_v8_holdouts.json"],
}
APPROVED_PATCHED_URLS = {"https://github.com/ASSERT-KTH/Proof-of-Patch"}


def blocked_fresh_holdout(root: Path, mode: str, *, split: str = FRESH_SPLIT, reason: str | None = None) -> dict[str, Any]:
    (root / split).mkdir(parents=True, exist_ok=True)
    return {
        "status": "BLOCKED",
        "fresh_holdout_status": "blocked_pending_approved_sources",
        "public_case_import_status": "blocked_pending_approved_public_case_sources",
        "reason": reason or "no approved fresh holdout source manifest was provided; no repositories were fetched",
        "mode": mode,
        "split": split,
        "case_count": 0,
        "answer_key_access": False,
        "writeup_access": False,
        "network_used_during_detection": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
    }


def has_fresh_source_manifest(root: Path, *, split: str = FRESH_SPLIT) -> bool:
    return any((root / "sources" / name).exists() for name in FRESH_SOURCE_MANIFESTS_BY_SPLIT.get(split, []))


def load_source_list(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(errors="replace"))
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return list(payload.get("sources") or payload.get("approved_sources") or [])
    raise SystemExit(f"source manifest must be list or object: {path}")


def run_git(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=cwd, text=True, capture_output=True, timeout=180, check=False)


def clone_or_reuse_exact(repo_url: str, raw_root: Path) -> dict[str, Any]:
    raw_root.parent.mkdir(parents=True, exist_ok=True)
    network_used = False
    if not raw_root.exists():
        result = run_git(["clone", "--depth", "1", repo_url, str(raw_root)])
        network_used = True
        if result.returncode != 0:
            return {"status": "FAIL", "repo_url": repo_url, "stderr": result.stderr[-2000:], "network_used": network_used}
    commit = run_git(["rev-parse", "HEAD"], cwd=raw_root)
    commit_hash = commit.stdout.strip() if commit.returncode == 0 else "unknown"
    license_files = [p.name for p in raw_root.glob("LICENSE*") if p.is_file()]
    license_note = "root license file present: " + ", ".join(license_files) if license_files else "license file not found at repository root; verify manually"
    return {"status": "PASS", "repo_url": repo_url, "raw_root": str(raw_root), "commit_hash": commit_hash, "license_note": license_note, "network_used": network_used}


def approved_fresh_manifest(root: Path, *, split: str = FRESH_SPLIT) -> Path | None:
    for name in FRESH_SOURCE_MANIFESTS_BY_SPLIT.get(split, []):
        path = root / "sources" / name
        if path.exists():
            return path
    return None


def source_repo_url(source: dict[str, Any]) -> str:
    return str(source.get("repository_url") or source.get("source_url") or source.get("source_path_or_url") or "")


def source_case_id(source: dict[str, Any]) -> str:
    return str(source.get("case_id") or source.get("fresh_case_id") or "")


def import_fresh_holdouts(root: Path, *, split: str = FRESH_SPLIT, use_approved_fallback: str = "") -> dict[str, Any]:
    ensure_public_corpus(root)
    manifest_path = approved_fresh_manifest(root, split=split)
    if manifest_path is None:
        return blocked_fresh_holdout(root, "import", split=split)
    sources = load_source_list(manifest_path)
    if use_approved_fallback:
        return activate_fresh_fallback(root, split=split, sources=sources, fallback_case_id=use_approved_fallback)
    cases: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    network_used = False
    fresh_root = root / split
    if fresh_root.exists():
        shutil.rmtree(fresh_root)
    fresh_root.mkdir(parents=True, exist_ok=True)
    approved_urls = APPROVED_FRESH_URLS_BY_SPLIT.get(split, set())
    approved_case_ids = APPROVED_FRESH_CASE_IDS_BY_SPLIT.get(split, set())
    for source in sources:
        case_id = source_case_id(source)
        repo_url = source_repo_url(source)
        fallback = bool(source.get("fallback_only")) or case_id.endswith("_fallback")
        if split in {FRESH_CONFIRMATION_SPLIT, FRESH_V6_SPLIT, FRESH_V8_SPLIT} and fallback:
            rows.append({"case_id": case_id, "repo_url": repo_url, "status": "SKIPPED", "reason": f"fallback source not used because primary {split} import is attempted first"})
            continue
        if repo_url not in approved_urls or case_id not in approved_case_ids:
            rows.append({"case_id": case_id, "repo_url": repo_url, "status": "BLOCKED", "reason": "not in exact approved fresh holdout set"})
            continue
        clone = clone_or_reuse_exact(repo_url, root / "sources" / "raw" / split / case_id)
        network_used = network_used or bool(clone.get("network_used"))
        if clone["status"] != "PASS":
            rows.append({"case_id": case_id, "repo_url": repo_url, **clone})
            continue
        project_root = detector_project_root(Path(clone["raw_root"]))
        mapping = sanitize_case(project_root, fresh_root / case_id, case_id=case_id)
        case = {
            **source,
            "case_id": case_id,
            "commit_hash": clone["commit_hash"],
            "license_note": clone["license_note"],
            "sanitized_root": f"{split}/{case_id}",
            "answer_key_path": f"expected_findings/{case_id}.json",
            "writeup_path": f"public_writeups/{case_id}.md",
            "scoring_enabled": False,
            "expected_extraction_status": "blocked_until_generated_outputs_frozen",
            "detector_forbidden_paths": ["expected_findings/", "public_writeups/", "reports/", "README.md", "issues/", "audit_reports/", "automated_findings/"],
        }
        cases.append(case)
        rows.append({"case_id": case_id, "repo_url": repo_url, "commit_hash": clone["commit_hash"], "license_note": clone["license_note"], "sanitized_hash": mapping["sanitized_hash"], "status": "IMPORTED"})
    (root / "sources" / f"{split}_import_log.json").write_text(json.dumps({"network_used": network_used, "rows": rows}, indent=2) + "\n")
    (root / f"{split}_manifest.json").write_text(json.dumps({"version": "1.0", "split": split, "cases": cases}, indent=2) + "\n")
    required = PRIMARY_FRESH_CASE_IDS_BY_SPLIT.get(split, APPROVED_FRESH_CASE_IDS_BY_SPLIT[FRESH_SPLIT])
    imported_required = {case["case_id"] for case in cases}.intersection(required)
    import_ok = imported_required == required
    return {"status": "PASS" if import_ok else "BLOCKED", "fresh_holdout_status": "imported" if import_ok else "blocked_partial_import", "network_used": network_used, "imported_count": len(cases), "case_count": len(cases), "required_case_count": len(required), "rows": rows}


def activate_fresh_fallback(root: Path, *, split: str, sources: list[dict[str, Any]], fallback_case_id: str) -> dict[str, Any]:
    approved_case_ids = APPROVED_FRESH_CASE_IDS_BY_SPLIT.get(split, set())
    primary_case_ids = PRIMARY_FRESH_CASE_IDS_BY_SPLIT.get(split, set())
    fallback_sources = [source for source in sources if source_case_id(source) == fallback_case_id]
    fallback_source = fallback_sources[0] if fallback_sources else {}
    fallback_repo_url = source_repo_url(fallback_source)
    approved_urls = APPROVED_FRESH_URLS_BY_SPLIT.get(split, set())
    rows: list[dict[str, Any]] = []
    if fallback_case_id not in approved_case_ids or not (fallback_source.get("fallback_only") or fallback_case_id.endswith("_fallback")) or fallback_repo_url not in approved_urls:
        return {"status": "BLOCKED", "split": split, "reason": "fallback is not in the exact approved fallback set", "fallback_case_id": fallback_case_id, "network_used": False, "rows": [{"case_id": fallback_case_id, "repo_url": fallback_repo_url, "status": "BLOCKED", "reason": "unapproved fallback"}]}

    existing_cases: list[dict[str, Any]] = []
    manifest_path = root / f"{split}_manifest.json"
    if manifest_path.exists():
        existing_cases = list((json.loads(manifest_path.read_text(errors="replace")) or {}).get("cases") or [])
    existing_case_ids = {str(case.get("case_id")) for case in existing_cases}
    missing_primary_ids = sorted(primary_case_ids - existing_case_ids)
    if not missing_primary_ids:
        return {"status": "BLOCKED", "split": split, "reason": "fallback not used because all primary cases are already imported", "fallback_case_id": fallback_case_id, "network_used": False, "case_count": len(existing_cases), "rows": [{"case_id": fallback_case_id, "repo_url": fallback_repo_url, "status": "SKIPPED", "reason": "all primary cases imported"}]}
    if fallback_case_id in existing_case_ids:
        return {"status": "BLOCKED", "split": split, "reason": "fallback already imported", "fallback_case_id": fallback_case_id, "network_used": False, "case_count": len(existing_cases), "rows": [{"case_id": fallback_case_id, "repo_url": fallback_repo_url, "status": "SKIPPED", "reason": "fallback already imported"}]}

    clone = clone_or_reuse_exact(fallback_repo_url, root / "sources" / "raw" / split / fallback_case_id)
    network_used = bool(clone.get("network_used"))
    if clone["status"] != "PASS":
        rows.append({"case_id": fallback_case_id, "repo_url": fallback_repo_url, **clone})
        return {"status": "BLOCKED", "split": split, "fresh_holdout_status": "blocked_fallback_import", "network_used": network_used, "imported_count": len(existing_cases), "case_count": len(existing_cases), "rows": rows, "blocked_primary_case_ids": missing_primary_ids}

    fresh_root = root / split
    fresh_root.mkdir(parents=True, exist_ok=True)
    project_root = detector_project_root(Path(clone["raw_root"]))
    mapping = sanitize_case(project_root, fresh_root / fallback_case_id, case_id=fallback_case_id)
    fallback_case = {
        **fallback_source,
        "case_id": fallback_case_id,
        "commit_hash": clone["commit_hash"],
        "license_note": clone["license_note"],
        "sanitized_root": f"{split}/{fallback_case_id}",
        "answer_key_path": f"expected_findings/{fallback_case_id}.json",
        "writeup_path": f"public_writeups/{fallback_case_id}.md",
        "scoring_enabled": False,
        "expected_extraction_status": "blocked_until_generated_outputs_frozen",
        "detector_forbidden_paths": ["expected_findings/", "public_writeups/", "reports/", "README.md", "issues/", "audit_reports/", "automated_findings/"],
        "fallback_replacement_for": missing_primary_ids[0],
    }
    effective_cases = [case for case in existing_cases if str(case.get("case_id")) in primary_case_ids]
    effective_cases.append(fallback_case)
    blocked_cases = [
        {
            "case_id": missing_primary_ids[0],
            "status": "blocked_clone_requires_credentials",
            "imported": False,
            "sanitized": False,
            "used_in_detection": False,
            "replacement": fallback_case_id,
        }
    ]
    effective_case_set = [str(case.get("case_id")) for case in effective_cases]
    manifest_path.write_text(json.dumps({"version": "1.0", "split": split, "effective_case_set": effective_case_set, "blocked_cases": blocked_cases, "cases": effective_cases}, indent=2) + "\n")
    rows.append({"case_id": fallback_case_id, "repo_url": fallback_repo_url, "commit_hash": clone["commit_hash"], "license_note": clone["license_note"], "sanitized_hash": mapping["sanitized_hash"], "status": "IMPORTED_AS_APPROVED_FALLBACK", "replacement_for": missing_primary_ids[0]})
    (root / "sources" / f"{split}_fallback_activation_log.json").write_text(json.dumps({"network_used": network_used, "blocked_primary_case_ids": missing_primary_ids, "approved_fallback_used": fallback_case_id, "effective_case_set": effective_case_set, "rows": rows}, indent=2) + "\n")
    return {"status": "PASS" if len(effective_cases) == len(primary_case_ids) else "BLOCKED", "split": split, "fresh_holdout_status": "fallback_activated", "network_used": network_used, "imported_count": len(effective_cases), "case_count": len(effective_cases), "required_case_count": len(primary_case_ids), "blocked_primary_case_ids": missing_primary_ids, "approved_fallback_used": fallback_case_id, "effective_case_set": effective_case_set, "rows": rows}


def import_patched_controls(root: Path) -> dict[str, Any]:
    ensure_public_corpus(root)
    manifest = root / "sources" / "approved_patched_control_sources.json"
    if not manifest.exists():
        return {"status": "BLOCKED", "patched_control_status": "blocked_pending_approved_sources", "reason": "no approved patched-control source manifest", "network_used": False, "imported_count": 0}
    sources = load_source_list(manifest)
    source = sources[0] if sources else {}
    repo_url = str(source.get("repository_url") or source.get("source_url") or "")
    if repo_url not in APPROVED_PATCHED_URLS:
        return {"status": "BLOCKED", "patched_control_status": "blocked_unapproved_source", "repo_url": repo_url, "network_used": False, "imported_count": 0}
    clone = clone_or_reuse_exact(repo_url, root / "sources" / "raw" / PATCHED_SPLIT / "proof_of_patch")
    network_used = bool(clone.get("network_used"))
    if clone["status"] != "PASS":
        return {"status": "FAIL", "patched_control_status": "clone_failed", "network_used": network_used, "source_error": clone, "imported_count": 0}
    (root / "sources" / "patched_control_import_log.json").write_text(json.dumps({"network_used": network_used, "clone": clone, "pair_import_status": "blocked_safe_pair_importer_not_implemented_without_patch_metadata"}, indent=2) + "\n")
    return {"status": "BLOCKED", "patched_control_status": "blocked_safe_pair_importer_not_implemented", "reason": "Proof-of-Patch cloned, but no safe automated vulnerable/patched pair importer is implemented without reading patch metadata before freeze", "network_used": network_used, "imported_count": 0, "raw_root": clone.get("raw_root"), "commit_hash": clone.get("commit_hash"), "license_note": clone.get("license_note")}


def sanitize_split(root: Path, split: str) -> dict[str, Any]:
    split_root = root / split
    if not split_root.exists() or not any(p.is_dir() for p in split_root.iterdir()):
        return {"status": "BLOCKED", "split": split, "reason": "no imported cases to sanitize", "sanitized_count": 0, "answer_key_access": False, "network_used": False, "secrets_accessed": False, "broadcasts_used": False}
    rows = []
    manifest_path = root / f"{split}_manifest.json"
    manifest_cases = []
    if manifest_path.exists():
        manifest_cases = list((json.loads(manifest_path.read_text(errors="replace")) or {}).get("cases") or [])
    case_ids = [str(case.get("case_id")) for case in manifest_cases] if manifest_cases else [p.name for p in sorted(split_root.iterdir()) if p.is_dir()]
    for case_id in case_ids:
        raw_root = root / "sources" / "raw" / split / case_id
        case_root = split_root / case_id
        mapping: dict[str, Any] = {}
        if raw_root.exists():
            project_root = detector_project_root(raw_root)
            mapping = sanitize_case(project_root, case_root, case_id=case_id)
        leakage = validate_no_leakage(case_root, source_only=False)
        blocks = list(leakage.get("blocks", []))
        if mapping and mapping.get("integrity_status") != "PASS":
            blocks.append("detector-visible Solidity source is empty while raw Solidity source exists")
        rows.append({"case_id": case_id, **leakage, "blocks": blocks, "status": "PASS" if not blocks else "FAIL", "sanitization_integrity": mapping or None})
    return {"status": "PASS" if all(r["status"] == "PASS" for r in rows) else "FAIL", "split": split, "sanitized_count": len(rows), "cases": rows, "answer_key_access": False, "network_used": False, "secrets_accessed": False, "broadcasts_used": False}


def split_case_ids(root: Path, split: str) -> list[str]:
    split_root = root / split
    return sorted(p.name for p in split_root.iterdir() if p.is_dir()) if split_root.exists() else []


def freeze_split_reports(root: Path, split: str) -> dict[str, Any]:
    case_ids = split_case_ids(root, split)
    if not case_ids:
        return {"status": "BLOCKED", "split": split, "reason": "no imported cases with generated outputs to freeze", "frozen_count": 0}
    rows = []
    for case_id in case_ids:
        for report_path in sorted((root / "generated_reports").glob(f"{case_id}_*.json")):
            report = json.loads(report_path.read_text(errors="replace"))
            if not verify_frozen_report(report):
                report = freeze_report(report)
                report_path.write_text(json.dumps(report, indent=2) + "\n")
            rows.append({"case_id": case_id, "report": report_path.name, "hash": report.get("report_hash"), "verified": verify_frozen_report(report)})
    return {"status": "PASS" if rows and all(r["verified"] for r in rows) else "BLOCKED", "split": split, "frozen_count": len(rows), "reports": rows}


def load_manifest(root: Path) -> dict[str, Any]:
    ensure_public_corpus(root)
    return json.loads((root / "corpus_manifest.json").read_text(errors="replace"))


def split_cases(manifest: dict[str, Any], mode: str) -> list[dict[str, Any]]:
    cases = manifest.get("cases", [])
    if mode in {"source-only", "source-plus-tests"}:
        return [c for c in cases if c.get("is_vulnerable") and not c.get("is_holdout") and not c.get("is_patched_control")]
    if mode == "patched-controls":
        return [c for c in cases if c.get("is_patched_control")]
    if mode == "holdout":
        return [c for c in cases if c.get("is_holdout")]
    return cases


def case_root(root: Path, case: dict[str, Any]) -> Path:
    split = "holdout" if case.get("is_holdout") else ("patched" if case.get("is_patched_control") else "vulnerable")
    return root / split / case["case_id"]


def enrich(lead: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(lead)
    evidence = enriched.get("external_evidence") or enriched.get("blind_evidence") or []
    if evidence:
        enriched["root_cause_rule"] = evidence[0].get("rule")
    enriched["report_ready"] = ((enriched.get("pipeline") or {}).get("final_status") == "REPORT_READY")
    return enriched


def run_detection(root: Path, mode: str) -> dict[str, Any]:
    manifest = load_manifest(root)
    cases = split_cases(manifest, mode)
    if not cases:
        return {"status": "BLOCKED", "public_case_import_status": manifest.get("public_case_import_status", "blocked_pending_approved_public_case_sources"), "reason": "no approved public cases available", "mode": mode, "case_count": 0, "answer_key_access": False, "writeup_access": False, "network_used_during_detection": False, "secrets_accessed": False, "broadcasts_used": False}
    include_tests = mode == "source-plus-tests"
    rows = []
    for case in cases:
        project = case_root(root, case)
        analysis = analyze_project(project, include_tests=include_tests)
        read_guard = validate_detection_read_set(analysis.get("read_files", []), source_only=(mode == "source-only"))
        converted = convert_analysis(analysis, with_poc=include_tests and case.get("is_vulnerable"), project_root=project)
        build = run_local_test(project, actually_run=False) if include_tests else None
        report = {
            "case_id": case["case_id"],
            "mode": mode,
            "source_name": case.get("source_name"),
            "read_files": analysis.get("read_files", []),
            "answer_key_read_during_detection": bool(analysis.get("answer_key_read")),
            "answer_key_loaded": False,
            "writeup_read_during_detection": False,
            "network_used": False,
            "secrets_accessed": False,
            "broadcasts_used": False,
            "read_guard": read_guard,
            "build": build,
            "findings": [enrich(lead) for lead in converted.get("leads", [])],
        }
        frozen = freeze_report(report)
        out = root / "generated_reports" / f"{case['case_id']}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(frozen, indent=2) + "\n")
        rows.append({"case_id": case["case_id"], "finding_count": len(report["findings"]), "read_guard": read_guard["status"], "report_path": out.relative_to(root).as_posix(), "report_hash": frozen["report_hash"]})
    return {"status": "PASS" if all(r["read_guard"] == "PASS" for r in rows) else "FAIL", "mode": mode, "classification": "public-blind-detection", "case_count": len(rows), "answer_key_access": False, "writeup_access": False, "network_used_during_detection": False, "secrets_accessed": False, "broadcasts_used": False, "cases": rows}


def freeze_reports(root: Path) -> dict[str, Any]:
    ensure_public_corpus(root)
    reports = sorted((root / "generated_reports").glob("*.json"))
    if not reports:
        return {"status": "BLOCKED", "reason": "no generated reports to freeze", "frozen_count": 0}
    rows = []
    for report_path in reports:
        report = json.loads(report_path.read_text(errors="replace"))
        if not verify_frozen_report(report):
            report = freeze_report(report)
            report_path.write_text(json.dumps(report, indent=2) + "\n")
        rows.append({"report": report_path.name, "hash": report.get("report_hash"), "verified": verify_frozen_report(report)})
    return {"status": "PASS", "frozen_count": len(rows), "reports": rows}


def run_mode(root: Path, mode: str) -> dict[str, Any]:
    ensure_public_corpus(root)
    if mode == "import":
        return import_public_corpus(root)
    if mode == "sanitize":
        result = sanitize_manifest(root)
        validation = validate_public_manifest(root)
        return {"mode": mode, **result, "manifest_validation": validation}
    if mode in {"source-only", "source-plus-tests", "patched-controls", "holdout"}:
        return run_detection(root, mode)
    if mode == "freeze":
        return freeze_reports(root)
    if mode == "score-only":
        result = score_public_benchmark(root)
        if result.get("status") == "BLOCKED":
            (root / "scoring").mkdir(parents=True, exist_ok=True)
            (root / "scoring" / "public_score.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    if mode == "adjudication-packets":
        return generate_packets(root)
    raise SystemExit(f"unknown mode: {mode}")


def run_split_mode(root: Path, mode: str, split: str) -> dict[str, Any]:
    ensure_public_corpus(root)
    if split in FRESH_SPLITS:
        if mode == "import":
            return import_fresh_holdouts(root, split=split)
        if not has_fresh_source_manifest(root, split=split):
            return blocked_fresh_holdout(root, mode, split=split)
        if mode == "sanitize":
            return sanitize_split(root, split)
        if mode == "freeze":
            return freeze_split_reports(root, split)
        if mode in {"score-only", "adjudication-packets"}:
            if mode == "score-only":
                from fresh_holdout_scoring import score_split

                return score_split(root, split=split, frozen_only=True)
            from fresh_adjudication_packet import generate_packets as generate_fresh_packets

            return generate_fresh_packets(root, split=split)
    if split == PATCHED_SPLIT:
        if mode == "import":
            return import_patched_controls(root)
        if mode == "sanitize":
            return sanitize_split(root, split)
        if mode == "freeze":
            return freeze_split_reports(root, split)
        if mode in {"score-only", "adjudication-packets"}:
            return {"status": "BLOCKED", "patched_control_status": "blocked_no_imported_patch_pairs", "reason": "no patched-control pairs were safely imported", "mode": mode, "split": split, "case_count": len(split_case_ids(root, split)), "answer_key_access": False, "writeup_access": False, "network_used": False, "secrets_accessed": False, "broadcasts_used": False}
    return run_mode(root, mode)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run public historical benchmark modes")
    p.add_argument("--mode", required=True, choices=sorted(MODES))
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="")
    p.add_argument("--use-approved-fallback", default="")
    args = p.parse_args(argv)
    if args.use_approved_fallback:
        if args.mode != "import" or not args.split:
            raise SystemExit("--use-approved-fallback requires --mode import and --split")
        result = import_fresh_holdouts(Path(args.root), split=args.split, use_approved_fallback=args.use_approved_fallback)
    else:
        result = run_split_mode(Path(args.root), args.mode, args.split) if args.split else run_mode(Path(args.root), args.mode)
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
