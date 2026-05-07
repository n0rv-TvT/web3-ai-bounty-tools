#!/usr/bin/env python3
"""Import approved public historical cases into a local benchmark corpus.

Network fetching is intentionally not implemented unless the user supplies an
approved local bundle or explicitly approves listed public sources. Without an
approved source manifest this returns a blocked status and performs no fetches.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from public_case_license_checker import check_case_license
from public_case_sanitizer import case_name_leaks, neutral_case_id, sanitize_case
from solidity_fixture_indexer import parse_contracts


PUBLIC_ROOT = Path(__file__).resolve().parents[1] / "benchmarks" / "public-historical-corpus"
SPLITS = ["sources", "vulnerable", "patched", "holdout", "expected_findings", "public_writeups", "generated_reports", "adjudication", "scoring"]
APPROVED_REPOSITORIES = {
    "https://github.com/OpenZeppelin/damn-vulnerable-defi",
    "https://github.com/smartbugs/smartbugs-curated",
    "https://github.com/smartbugs/smartbugs-wild",
    "https://github.com/code-423n4/2023-04-eigenlayer",
    "https://github.com/code-423n4/2023-10-canto",
    "https://github.com/code-423n4/2023-10-wildcat",
    "https://github.com/code-423n4/2023-11-kelp",
    "https://github.com/code-423n4/2023-10-badger",
}
ORG_DISCOVERY_ONLY = {"https://github.com/code-423n4"}

SMARTBUGS_PREFERRED_CASES = [
    {"path": "dataset/reentrancy/simple_dao.sol", "rule": "external_call_before_state_update", "protocol_type": "vault"},
    {"path": "dataset/access_control/incorrect_constructor_name1.sol", "rule": "initializer_without_guard", "protocol_type": "governance"},
    {"path": "dataset/access_control/simple_suicide.sol", "rule": "unprotected_selfdestruct", "protocol_type": "other"},
    {"path": "dataset/arithmetic/insecure_transfer.sol", "rule": "unchecked_arithmetic_pre_solidity_08", "protocol_type": "other"},
    {"path": "dataset/bad_randomness/guess_the_random_number.sol", "rule": "miner_controlled_randomness", "protocol_type": "other"},
    {"path": "dataset/unchecked_low_level_calls/unchecked_return_value.sol", "rule": "unchecked_low_level_call_return", "protocol_type": "other"},
]

RULE_EXPECTATIONS = {
    "external_call_before_state_update": {"bug_class": "reentrancy", "affected_asset": "ETH or native asset held by the vault", "impact_type": "stolen-funds", "expected_severity": "Critical", "exploit_path_tokens": ["reenters", "drains"]},
    "initializer_without_guard": {"bug_class": "proxy-initialization", "affected_asset": "owner-controlled protocol assets", "impact_type": "unauthorized-privileged-action", "expected_severity": "Critical", "exploit_path_tokens": ["initializer", "owner"]},
    "unprotected_selfdestruct": {"bug_class": "access-control", "affected_asset": "contract ETH balance and contract liveness", "impact_type": "stolen-funds", "expected_severity": "Critical", "exploit_path_tokens": ["destruct", "eth"]},
    "unchecked_arithmetic_pre_solidity_08": {"bug_class": "arithmetic-overflow", "affected_asset": "token balances or accounting state", "impact_type": "stolen-funds", "expected_severity": "High", "exploit_path_tokens": ["overflow", "balances"]},
    "miner_controlled_randomness": {"bug_class": "bad-randomness", "affected_asset": "lottery or wagered ETH prize pool", "impact_type": "stolen-funds", "expected_severity": "Medium", "exploit_path_tokens": ["randomness", "payout"]},
    "unchecked_low_level_call_return": {"bug_class": "unchecked-low-level-call", "affected_asset": "ETH or token transfer outcome", "impact_type": "frozen-funds", "expected_severity": "Medium", "exploit_path_tokens": ["low-level call", "succeeded"]},
}


def ensure_public_corpus(root: Path = PUBLIC_ROOT) -> None:
    for part in SPLITS:
        (root / part).mkdir(parents=True, exist_ok=True)
    readme = root / "README.md"
    if not readme.exists():
        readme.write_text("# Public Historical Corpus\n\nNo public sources have been approved/imported yet. Detection must not read writeups or expected findings.\n")
    manifest = root / "corpus_manifest.json"
    if not manifest.exists():
        manifest.write_text(json.dumps({"version": "1.0", "public_case_import_status": "blocked_pending_approved_public_case_sources", "cases": []}, indent=2) + "\n")


def default_approved_sources_manifest(root: Path = PUBLIC_ROOT) -> Path | None:
    candidate = root / "sources" / "approved_sources.json"
    return candidate if candidate.exists() else None


def blocked_status(root: Path = PUBLIC_ROOT) -> dict[str, Any]:
    ensure_public_corpus(root)
    return {
        "status": "BLOCKED",
        "public_case_import_status": "blocked_pending_approved_public_case_sources",
        "reason": "network/public source import requires explicit approval or a local approved case bundle",
        "network_used": False,
        "imported_count": 0,
        "root": str(root),
    }


def load_source_manifest(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(errors="replace"))
    if isinstance(raw, list):
        return {"approved": True, "sources": raw, "approval_model": "APPROVED_SOURCE_LIST"}
    if isinstance(raw, dict):
        return raw
    raise SystemExit("approved source manifest must be an object or a list")


def run_git(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=cwd, text=True, capture_output=True, timeout=120, check=False)


def clone_or_reuse_source(source: dict[str, Any], root: Path) -> dict[str, Any]:
    repo_url = str(source.get("repository_url") or source.get("source_url") or "")
    source_id = str(source.get("case_id") or "source_unknown")
    if repo_url in ORG_DISCOVERY_ONLY:
        return {"status": "SKIPPED", "reason": "organization source is discovery-only and is not imported wholesale", "repo_url": repo_url, "source_id": source_id}
    if repo_url not in APPROVED_REPOSITORIES:
        return {"status": "BLOCKED", "reason": "repository URL is not in the exact approved source list", "repo_url": repo_url, "source_id": source_id}
    raw_root = root / "sources" / "raw" / source_id
    raw_root.parent.mkdir(parents=True, exist_ok=True)
    network_used = False
    if not raw_root.exists():
        completed = run_git(["clone", "--depth", "1", repo_url, str(raw_root)])
        network_used = True
        if completed.returncode != 0:
            return {"status": "FAIL", "reason": "git clone failed", "repo_url": repo_url, "source_id": source_id, "stderr": completed.stderr[-2000:], "network_used": network_used}
    commit = run_git(["rev-parse", "HEAD"], cwd=raw_root)
    commit_hash = commit.stdout.strip() if commit.returncode == 0 else str(source.get("commit_hash") or "unknown_local_snapshot")
    license_files = [p.relative_to(raw_root).as_posix() for p in raw_root.glob("LICENSE*") if p.is_file()]
    license_note = f"root license file present: {', '.join(license_files)}" if license_files else f"license file not found at repository root; manifest note: {source.get('license_note', 'verify manually')}"
    return {"status": "PASS", "repo_url": repo_url, "source_id": source_id, "raw_root": raw_root, "commit_hash": commit_hash, "license_note": license_note, "network_used": network_used}


def strip_public_labels(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//.*", "", text)
    return "\n".join(line.rstrip() for line in text.splitlines() if line.strip()) + "\n"


def stage_single_solidity_file(raw_root: Path, rel_path: str, staging_root: Path) -> Path:
    if staging_root.exists():
        shutil.rmtree(staging_root)
    (staging_root / "src").mkdir(parents=True, exist_ok=True)
    src = raw_root / rel_path
    cleaned = strip_public_labels(src.read_text(errors="replace"))
    staged = staging_root / "src" / "System.sol"
    staged.write_text(cleaned)
    return staged


def infer_contract_function_for_line(source_path: Path, original_line: int | None = None) -> tuple[str, str]:
    text = source_path.read_text(errors="replace")
    contracts = parse_contracts(text)
    if not contracts:
        return "UnknownContract", "unknown"
    if original_line is not None:
        for contract in contracts:
            if contract.get("start_line", 0) <= original_line <= contract.get("end_line", 0):
                for fn in contract.get("functions", []):
                    if fn.get("start_line", 0) <= original_line <= fn.get("end_line", 0):
                        return contract["name"], fn["name"]
                return contract["name"], (contract.get("functions") or [{"name": "unknown"}])[0]["name"]
    first_contract = contracts[0]
    first_fn = (first_contract.get("functions") or [{"name": "unknown"}])[0]
    return first_contract["name"], first_fn["name"]


def first_vulnerability_line(raw_root: Path, rel_path: str) -> int | None:
    vuln_path = raw_root / "vulnerabilities.json"
    if not vuln_path.exists():
        return None
    try:
        rows = json.loads(vuln_path.read_text(errors="replace"))
    except json.JSONDecodeError:
        return None
    for row in rows:
        if row.get("path") == rel_path and row.get("vulnerabilities"):
            lines = row["vulnerabilities"][0].get("lines") or []
            return int(lines[0]) if lines else None
    return None


def write_expected_finding(root: Path, case: dict[str, Any], *, rule: str, contract: str, function: str, original_rel_path: str) -> None:
    spec = RULE_EXPECTATIONS[rule]
    payload = {
        "case_id": case["case_id"],
        "is_vulnerable": case.get("is_vulnerable", True),
        "is_patched_control": case.get("is_patched_control", False),
        "source_type": case.get("source_type"),
        "source_reference": original_rel_path,
        "bug_class": spec["bug_class"],
        "root_cause_rule": rule,
        "source_file": "src/System.sol",
        "affected_contract": contract,
        "affected_function": function,
        "affected_asset": spec["affected_asset"],
        "impact_type": spec["impact_type"],
        "expected_severity": spec["expected_severity"],
        "exploit_path_tokens": spec["exploit_path_tokens"],
        "expected_no_report_ready": spec["expected_severity"] == "Medium",
    }
    (root / "expected_findings" / f"{case['case_id']}.json").write_text(json.dumps(payload, indent=2) + "\n")


def detector_case(source: dict[str, Any], case_id: str, *, commit_hash: str, license_note: str, protocol_type: str | None = None) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "source_type": source.get("source_type", "public_historical"),
        "source_name": source.get("source_name", "Approved public source"),
        "source_url": source.get("source_url", source.get("repository_url", "")),
        "license_note": license_note,
        "commit_hash": commit_hash,
        "protocol_type": protocol_type or source.get("protocol_type", "other"),
        "language": "Solidity",
        "framework": source.get("framework", "none"),
        "is_vulnerable": bool(source.get("is_vulnerable", True)),
        "is_patched_control": False,
        "is_holdout": bool(source.get("is_holdout", False)),
        "detector_allowed_paths": ["src/", "contracts/"],
        "detector_forbidden_paths": ["expected_findings/", "public_writeups/", "reports/", "README.md", "issues/", "audit_reports/"],
        "answer_key_path": f"expected_findings/{case_id}.json",
        "writeup_path": f"public_writeups/{case_id}.md",
        "safety": {"network_allowed_during_detection": False, "secrets_allowed": False, "broadcast_allowed": False, "deployment_scripts_allowed": False},
    }


def import_local_mock_cases(source_manifest: Path, root: Path = PUBLIC_ROOT) -> dict[str, Any]:
    ensure_public_corpus(root)
    spec = load_source_manifest(source_manifest)
    if not spec.get("approved"):
        return blocked_status(root)
    cases: list[dict[str, Any]] = []
    log_rows: list[dict[str, Any]] = []
    for idx, source in enumerate(spec.get("sources", []), start=1):
        if source.get("source_type") != "local_mock":
            return {"status": "BLOCKED", "public_case_import_status": "blocked_pending_network_or_local_case_bundle", "network_used": False, "imported_count": len(cases)}
        license_check = check_case_license({**source, "case_id": neutral_case_id(idx)})
        if license_check["status"] != "PASS":
            return {"status": "FAIL", "blocks": license_check["blocks"], "network_used": False}
        split = "holdout" if source.get("is_holdout") else ("patched" if source.get("is_patched_control") else "vulnerable")
        case_id = neutral_case_id(idx)
        src_root = Path(source["local_path"])
        dst_root = root / split / case_id
        mapping = sanitize_case(src_root, dst_root, case_id=case_id)
        expected_src = Path(source.get("expected_finding_path", ""))
        writeup_src = Path(source.get("writeup_path", ""))
        if expected_src.exists():
            shutil.copy2(expected_src, root / "expected_findings" / f"{case_id}.json")
        else:
            (root / "expected_findings" / f"{case_id}.json").write_text(json.dumps({"case_id": case_id, "is_vulnerable": source.get("is_vulnerable", True), "is_patched_control": source.get("is_patched_control", False)}, indent=2) + "\n")
        if writeup_src.exists():
            shutil.copy2(writeup_src, root / "public_writeups" / f"{case_id}.md")
        else:
            (root / "public_writeups" / f"{case_id}.md").write_text("Local mock public writeup placeholder. Forbidden during detection.\n")
        case = {
            "case_id": case_id,
            "source_type": source.get("source_type", "local_mock"),
            "source_name": source["source_name"],
            "source_url": source.get("source_url", ""),
            "license_note": source["license_note"],
            "commit_hash": source.get("commit_hash", "not_applicable"),
            "protocol_type": source.get("protocol_type", "other"),
            "language": "Solidity",
            "framework": source.get("framework", "none"),
            "is_vulnerable": bool(source.get("is_vulnerable", True)),
            "is_patched_control": bool(source.get("is_patched_control", False)),
            "is_holdout": bool(source.get("is_holdout", False)),
            "detector_allowed_paths": ["src/", "contracts/"],
            "detector_forbidden_paths": ["expected_findings/", "public_writeups/", "reports/", "README.md", "issues/", "audit_reports/"],
            "answer_key_path": f"expected_findings/{case_id}.json",
            "writeup_path": f"public_writeups/{case_id}.md",
            "safety": {"network_allowed_during_detection": False, "secrets_allowed": False, "broadcast_allowed": False, "deployment_scripts_allowed": False},
        }
        cases.append(case)
        log_rows.append({"case_id": case_id, "source_name": source["source_name"], "sanitized_hash": mapping["sanitized_hash"]})
    manifest = {"version": "1.0", "public_case_import_status": "local_mock_imported", "cases": cases}
    (root / "corpus_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    import_log = {"imported_at": datetime.now(timezone.utc).isoformat(), "network_used": False, "imported_count": len(cases), "rows": log_rows}
    (root / "sources" / "import_log.json").write_text(json.dumps(import_log, indent=2) + "\n")
    return {"status": "PASS", "public_case_import_status": "local_mock_imported", "network_used": False, "imported_count": len(cases), "import_log": "sources/import_log.json"}


def reset_import_outputs(root: Path) -> None:
    preserved_scoring: dict[str, str] = {}
    scoring = root / "scoring"
    for name in [
        "detector_baseline_lock.json",
        "detector_repair_lock.json",
        "spent_holdout_registry.json",
        "spent_regression_results.json",
        "status_classification.json",
        "generalization_repair_plan.json",
        "independent_holdout_evaluation_plan.md",
    ]:
        path = scoring / name
        if path.exists():
            preserved_scoring[name] = path.read_text(errors="replace")
    for part in ["vulnerable", "patched", "holdout", "expected_findings", "public_writeups", "generated_reports", "adjudication", "scoring"]:
        target = root / part
        if target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True, exist_ok=True)
    for name, content in preserved_scoring.items():
        (scoring / name).write_text(content)


def split_for_case(case: dict[str, Any]) -> str:
    return "holdout" if case.get("is_holdout") else ("patched" if case.get("is_patched_control") else "vulnerable")


def detector_project_root(raw_root: Path) -> Path:
    """Choose the detector-visible project root without reading docs or reports."""
    if (raw_root / "src").exists() or (raw_root / "contracts").exists():
        return raw_root
    candidates: list[Path] = []
    for child in sorted(p for p in raw_root.iterdir() if p.is_dir()):
        if child.name.startswith(".") or child.name in {".git", "node_modules", "lib"}:
            continue
        if (child / "src").exists() or (child / "contracts").exists():
            candidates.append(child)
    return candidates[0] if len(candidates) == 1 else raw_root


def import_smartbugs_curated_cases(source: dict[str, Any], clone: dict[str, Any], root: Path, cases: list[dict[str, Any]], log_rows: list[dict[str, Any]]) -> None:
    raw_root = Path(clone["raw_root"])
    for preferred in SMARTBUGS_PREFERRED_CASES:
        rel_path = preferred["path"]
        if not (raw_root / rel_path).exists():
            log_rows.append({"source_id": clone["source_id"], "status": "SKIPPED", "reason": "preferred SmartBugs case missing", "source_reference": rel_path})
            continue
        case_id = neutral_case_id(len(cases) + 1)
        staging_root = root / "sources" / "staged" / case_id
        stage_single_solidity_file(raw_root, rel_path, staging_root)
        vuln_line = first_vulnerability_line(raw_root, rel_path)
        contract, function = infer_contract_function_for_line(raw_root / rel_path, vuln_line)
        case = detector_case(source, case_id, commit_hash=clone["commit_hash"], license_note=clone["license_note"], protocol_type=preferred.get("protocol_type"))
        case["framework"] = "none"
        license_check = check_case_license(case)
        if license_check["status"] != "PASS":
            raise SystemExit("approved public case failed metadata check: " + "; ".join(license_check["blocks"]))
        dst_root = root / split_for_case(case) / case_id
        mapping = sanitize_case(staging_root, dst_root, case_id=case_id)
        write_expected_finding(root, case, rule=preferred["rule"], contract=contract, function=function, original_rel_path=rel_path)
        (root / "public_writeups" / f"{case_id}.md").write_text(
            "SmartBugs Curated label metadata is stored as the answer key and is forbidden during detection.\n"
        )
        case["source_case_reference"] = rel_path
        case["scoring_enabled"] = True
        cases.append(case)
        log_rows.append({"case_id": case_id, "source_id": clone["source_id"], "source_name": source.get("source_name"), "source_reference": rel_path, "root_cause_rule": preferred["rule"], "sanitized_hash": mapping["sanitized_hash"], "status": "IMPORTED"})


def import_code4rena_contest_holdout(source: dict[str, Any], clone: dict[str, Any], root: Path, cases: list[dict[str, Any]], log_rows: list[dict[str, Any]]) -> None:
    raw_root = Path(clone["raw_root"])
    project_root = detector_project_root(raw_root)
    requested_case_id = str(source.get("case_id") or "")
    case_id = requested_case_id if requested_case_id and not case_name_leaks(requested_case_id) else neutral_case_id(len(cases) + 1)
    case = detector_case(source, case_id, commit_hash=clone["commit_hash"], license_note=clone["license_note"], protocol_type=source.get("protocol_type", "staking"))
    case["source_type"] = source.get("source_type", "public_contest")
    case["framework"] = "Foundry" if (project_root / "foundry.toml").exists() else case.get("framework", "unknown")
    case["is_vulnerable"] = True
    case["is_holdout"] = True
    case["source_case_reference"] = str(source.get("repository_url") or source.get("source_url"))
    case["expected_source_url"] = str(source.get("expected_finding_source") or "")
    case["scoring_enabled"] = False
    case["expected_extraction_status"] = "blocked_until_generated_report_frozen"
    license_check = check_case_license(case)
    if license_check["status"] != "PASS":
        raise SystemExit("approved contest case failed metadata check: " + "; ".join(license_check["blocks"]))
    dst_root = root / "holdout" / case_id
    mapping = sanitize_case(project_root, dst_root, case_id=case_id)
    (root / "public_writeups" / f"{case_id}.md").write_text(
        "Public contest report/writeup placeholder. The actual report must only be fetched/read after generated reports are frozen.\n"
    )
    cases.append(case)
    log_rows.append({"case_id": case_id, "source_id": clone["source_id"], "source_name": source.get("source_name"), "source_reference": case["source_case_reference"], "detector_project_root": project_root.relative_to(raw_root).as_posix() if project_root != raw_root else ".", "sanitized_hash": mapping["sanitized_hash"], "status": "IMPORTED_HOLDOUT_PENDING_EXPECTED_EXTRACTION"})


def import_approved_source_list(source_manifest: Path, root: Path = PUBLIC_ROOT) -> dict[str, Any]:
    ensure_public_corpus(root)
    reset_import_outputs(root)
    spec = load_source_manifest(source_manifest)
    if not spec.get("approved"):
        return blocked_status(root)
    cases: list[dict[str, Any]] = []
    log_rows: list[dict[str, Any]] = []
    skipped_sources: list[dict[str, Any]] = []
    network_used = False
    for source in spec.get("sources", []):
        if source.get("source_type") == "local_mock":
            skipped_sources.append({"source_id": source.get("case_id"), "source_name": source.get("source_name"), "reason": "local_mock source ignored in approved public-source-list importer"})
            continue
        repo_url = str(source.get("repository_url") or source.get("source_url") or "")
        if repo_url in ORG_DISCOVERY_ONLY:
            skipped_sources.append({"source_id": source.get("case_id"), "source_name": source.get("source_name"), "reason": "organization source is discovery-only; request per-repository approval before importing"})
            continue
        if repo_url == "https://github.com/smartbugs/smartbugs-wild":
            clone = clone_or_reuse_source(source, root)
            network_used = network_used or bool(clone.get("network_used"))
            skipped_sources.append({"source_id": source.get("case_id"), "source_name": source.get("source_name"), "reason": "SmartBugs Wild has no confirmed per-case ground truth in this importer; not scoring it as holdout", "clone_status": clone.get("status")})
            continue
        clone = clone_or_reuse_source(source, root)
        network_used = network_used or bool(clone.get("network_used"))
        if clone["status"] == "BLOCKED":
            return {"status": "BLOCKED", "public_case_import_status": "blocked_unapproved_public_source", "network_used": network_used, "imported_count": len(cases), "reason": clone["reason"], "repo_url": clone["repo_url"]}
        if clone["status"] == "FAIL":
            return {"status": "FAIL", "public_case_import_status": "failed_fetching_approved_public_source", "network_used": network_used, "imported_count": len(cases), "source_error": clone}
        if repo_url == "https://github.com/smartbugs/smartbugs-curated":
            import_smartbugs_curated_cases(source, clone, root, cases, log_rows)
        elif repo_url.startswith("https://github.com/code-423n4/") and source.get("is_holdout"):
            import_code4rena_contest_holdout(source, clone, root, cases, log_rows)
        else:
            skipped_sources.append({"source_id": source.get("case_id"), "source_name": source.get("source_name"), "reason": "source fetched but not scored because no machine-readable expected-finding importer is implemented yet", "commit_hash": clone.get("commit_hash"), "license_note": clone.get("license_note")})
    status_text = "approved_source_list_imported_partial" if cases else "blocked_no_scored_public_cases_imported"
    manifest = {"version": "1.0", "public_case_import_status": status_text, "cases": cases}
    (root / "corpus_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    import_log = {"imported_at": datetime.now(timezone.utc).isoformat(), "approval_model": spec.get("approval_model", "APPROVED_SOURCE_LIST"), "network_used": network_used, "source_manifest": str(source_manifest), "imported_count": len(cases), "skipped_sources": skipped_sources, "rows": log_rows}
    (root / "sources" / "import_log.json").write_text(json.dumps(import_log, indent=2) + "\n")
    return {"status": "PASS" if cases else "BLOCKED", "public_case_import_status": status_text, "network_used": network_used, "imported_count": len(cases), "skipped_source_count": len(skipped_sources), "import_log": "sources/import_log.json"}


def import_public_corpus(root: Path = PUBLIC_ROOT, *, approved_sources_manifest: Path | None = None) -> dict[str, Any]:
    if approved_sources_manifest is None:
        approved_sources_manifest = default_approved_sources_manifest(root)
        if approved_sources_manifest is None:
            return blocked_status(root)
    spec = load_source_manifest(approved_sources_manifest)
    if spec.get("sources") and all(source.get("source_type") == "local_mock" for source in spec.get("sources", [])):
        return import_local_mock_cases(approved_sources_manifest, root=root)
    return import_approved_source_list(approved_sources_manifest, root=root)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Import approved public historical benchmark cases")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--approved-sources-manifest")
    args = p.parse_args(argv)
    result = import_public_corpus(Path(args.root), approved_sources_manifest=Path(args.approved_sources_manifest) if args.approved_sources_manifest else None)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
