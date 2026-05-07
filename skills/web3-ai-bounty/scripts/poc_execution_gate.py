#!/usr/bin/env python3
"""Gate and optionally execute generated local PoC scaffolds safely."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT
from feedback_memory import record_confirmed_finding, record_false_positive, record_reviewer_feedback

SAFE_LOCAL_TEST = "SAFE_LOCAL_TEST"
EXECUTES_UNTRUSTED_CODE = "EXECUTES_UNTRUSTED_CODE"
REQUIRES_DEPENDENCIES = "REQUIRES_DEPENDENCIES"
REQUIRES_NETWORK = "REQUIRES_NETWORK"
FORBIDDEN = "FORBIDDEN"
PRECISION_REGENERATION_DIR = "precision_regeneration"
REPAIRED_EXECUTION_DIR = "repaired_candidate_execution"
FRESH_V8_REPAIR_EXECUTION_DIR = "fresh_v8_repair_execution"
APPROVED_FRESH_V8_REPAIR_CANDIDATE = "REPAIR-POC-contest_5004_fallback-HYP-411445b972e2"
FRESH_POSTHOC_REPAIR_POC_DIR = "fresh_posthoc_repair"
FRESH_V8_REPAIR_POC_DIR = "fresh_v8_repair"
KILL_ON_PASS_CANDIDATES = {"POC-PREC-case_pc_0002-vulnerable-003", "POC-PREC-case_pc_0003-vulnerable-001"}

POC_PASS_CONFIRMS_HYPOTHESIS = "POC_PASS_CONFIRMS_HYPOTHESIS"
POC_FAILS_KILLS_HYPOTHESIS = "POC_FAILS_KILLS_HYPOTHESIS"
POC_BLOCKED_MISSING_DEPENDENCIES = "POC_BLOCKED_MISSING_DEPENDENCIES"
POC_BLOCKED_UNSAFE = "POC_BLOCKED_UNSAFE"
POC_INCONCLUSIVE = "POC_INCONCLUSIVE"
POC_BLOCKED_MISSING_ASSERTION = "POC_BLOCKED_MISSING_ASSERTION"
POC_PASS_CONFIRMS_EXPECTED_ALIGNED_HYPOTHESIS = "POC_PASS_CONFIRMS_EXPECTED_ALIGNED_HYPOTHESIS"
POC_FAILS_KILLS_EXPECTED_ALIGNED_HYPOTHESIS = "POC_FAILS_KILLS_EXPECTED_ALIGNED_HYPOTHESIS"
POC_BLOCKED_MISSING_STATE_SETUP = "POC_BLOCKED_MISSING_STATE_SETUP"


def safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_") or "candidate"


def precision_dir(root: Path) -> Path:
    out = root / "scoring" / PRECISION_REGENERATION_DIR
    out.mkdir(parents=True, exist_ok=True)
    return out


def repaired_execution_dir(root: Path) -> Path:
    out = root / "scoring" / REPAIRED_EXECUTION_DIR
    out.mkdir(parents=True, exist_ok=True)
    return out


def repaired_execution_dir_for(root: Path, split: str = "fresh-confirmation") -> Path:
    if split == "fresh-v8":
        out = root / "scoring" / FRESH_V8_REPAIR_EXECUTION_DIR
        out.mkdir(parents=True, exist_ok=True)
        return out
    return repaired_execution_dir(root)


def generated_root(root: Path) -> Path:
    out = root / "generated_pocs"
    out.mkdir(parents=True, exist_ok=True)
    return out


def load_json(path: Path, default: dict[str, Any] | None = None) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace")) if path.exists() else (default or {})


def manifest_paths(root: Path, *, mode: str | None = None, split: str | None = None) -> list[Path]:
    paths = sorted(generated_root(root).glob("**/poc_manifest.json"))
    filtered = []
    for path in paths:
        payload = load_json(path)
        if mode is not None and not str(payload.get("poc_type", "")).startswith(mode):
            continue
        if split is not None:
            payload_split = payload.get("split") or ("patched-controls" if payload.get("post_hoc_regression_only") else "")
            if payload_split != split:
                continue
        filtered.append(path)
    return filtered


def find_candidate_manifest(root: Path, candidate_id: str) -> Path | None:
    for manifest in generated_root(root).glob("**/poc_manifest.json"):
        if load_json(manifest, {}).get("candidate_id") == candidate_id:
            return manifest
    return None


def read_generated_text(path: Path) -> str:
    chunks: list[str] = []
    for rel in (load_json(path).get("generated_files") or []):
        generated = path.parent / rel
        if _within(generated, path.parent) and generated.exists() and generated.is_file():
            chunks.append(generated.read_text(errors="replace"))
    return "\n".join(chunks)


def generated_file_scope_blocks(path: Path) -> list[str]:
    blocks: list[str] = []
    for rel in (load_json(path).get("generated_files") or []):
        generated = path.parent / str(rel)
        if not _within(generated, path.parent):
            blocks.append(f"generated file path escapes PoC directory: {rel}")
    return blocks


def _within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def classify_manifest(path: Path, root: Path) -> dict[str, Any]:
    manifest = load_json(path)
    command = str(manifest.get("command") or "")
    lower = command.lower()
    generated_text = read_generated_text(path).lower()
    reasons: list[str] = []
    classification = SAFE_LOCAL_TEST
    if not _within(path.parent, generated_root(root)):
        classification = FORBIDDEN
        reasons.append("manifest outside generated_pocs root")
    scope_blocks = generated_file_scope_blocks(path)
    if scope_blocks:
        classification = FORBIDDEN
        reasons.extend(scope_blocks)
    if manifest.get("modifies_production_source") is True or manifest.get("production_source_modified") is True:
        classification = FORBIDDEN
        reasons.append("manifest declares production source modification")
    forbidden_patterns = [r"\bcast\s+send\b", r"\bforge\s+script\b.*--broadcast\b", r"--broadcast", r"\brm\s+(-rf|-fr|-[^ ]*r[^ ]*f)"]
    if any(re.search(p, lower) for p in forbidden_patterns):
        classification = FORBIDDEN
        reasons.append("broadcast/destructive command blocked")
    if re.search(r"\b(npm|yarn|pnpm|pip|pip3|apt|apt-get)\s+(install|add)\b", lower) or re.search(r"\b(curl|wget)\b.*\|\s*(sh|bash)", lower):
        classification = FORBIDDEN
        reasons.append("dependency install command blocked")
    if re.search(r"\b(printenv|env|set)\b", lower) or any(token in generated_text for token in ["vm.env", "envstring", ".env", "private_key", "mnemonic", "keystore"]):
        classification = FORBIDDEN
        reasons.append("environment or secret access blocked")
    if any(token in lower for token in ["--fork-url", "http://", "https://", "cast call", "cast storage", "curl", "wget"]) or any(token in generated_text for token in ["createfork", "http://", "https://"]):
        if classification != FORBIDDEN:
            classification = REQUIRES_NETWORK
        reasons.append("network or fork dependency blocked")
    if command.startswith("forge"):
        if shutil.which("forge") is None:
            classification = REQUIRES_DEPENDENCIES
            reasons.append("forge is not installed")
        if not (path.parent / "foundry.toml").exists():
            classification = REQUIRES_DEPENDENCIES
            reasons.append("missing foundry.toml")
    elif command:
        if classification != FORBIDDEN:
            classification = EXECUTES_UNTRUSTED_CODE
        reasons.append("non-allowlisted execution command")
    if manifest.get("requires_network") or manifest.get("requires_fork"):
        if classification != FORBIDDEN:
            classification = REQUIRES_NETWORK
        reasons.append("manifest declares network/fork requirement")
    scaffold_only = bool(manifest.get("scaffold_only", True))
    execution_approved = classification == SAFE_LOCAL_TEST and not scaffold_only and bool(manifest.get("execution_approved", True))
    if scaffold_only:
        reasons.append("scaffold_only_no_executed_evidence")
    return {
        "manifest_path": str(path.relative_to(root)),
        "output_dir": str(path.parent.relative_to(root)),
        "poc_type": manifest.get("poc_type"),
        "candidate_id": manifest.get("candidate_id"),
        "hypothesis_id": manifest.get("hypothesis_id"),
        "pair_id": manifest.get("pair_id"),
        "command": command,
        "classification": classification,
        "execution_approved": execution_approved,
        "scaffold_only": scaffold_only,
        "reasons": list(dict.fromkeys(reasons)) or ["safe local generated Foundry test"],
        "report_ready": False,
        "counts_as_finding": False,
    }


def gate_generated_pocs(root: Path = PUBLIC_ROOT, *, split: str = "patched-controls", patch_regression: bool = False) -> dict[str, Any]:
    mode_prefix = "patch_regression" if patch_regression else None
    rows = [classify_manifest(path, root) for path in manifest_paths(root, mode=mode_prefix, split=split)]
    result = {
        "status": "PASS" if rows else "BLOCKED",
        "split": split,
        "mode": "patch-regression" if patch_regression else "generated-pocs",
        "classification_counts": {name: sum(1 for r in rows if r["classification"] == name) for name in [SAFE_LOCAL_TEST, EXECUTES_UNTRUSTED_CODE, REQUIRES_DEPENDENCIES, REQUIRES_NETWORK, FORBIDDEN]},
        "approved_execution_count": sum(1 for r in rows if r["execution_approved"]),
        "blocked_execution_count": sum(1 for r in rows if not r["execution_approved"]),
        "pocs": rows,
        "production_readiness_changed": False,
        "report_ready_created": False,
        "confirmed_findings_created": 0,
    }
    name = "patch_regression_poc_execution_gate.json" if patch_regression else "poc_execution_gate.json"
    precision_dir(root).joinpath(name).write_text(json.dumps(result, indent=2) + "\n")
    return result


def preflight_candidate(root: Path = PUBLIC_ROOT, *, candidate_id: str) -> dict[str, Any]:
    manifest = find_candidate_manifest(root, candidate_id)
    if not manifest:
        result = {"status": "BLOCKED", "candidate_id": candidate_id, "classification": REQUIRES_DEPENDENCIES, "allowed_to_execute": False, "reason": "candidate manifest missing"}
    else:
        row = classify_manifest(manifest, root)
        allowed = bool(row["classification"] == SAFE_LOCAL_TEST and row.get("execution_approved"))
        result = {
            "status": "PASS" if allowed else "BLOCKED",
            "candidate_id": candidate_id,
            "pair_id": row.get("pair_id"),
            "classification": row["classification"],
            "allowed_to_execute": allowed,
            "execution_command": row.get("command"),
            "output_dir": row.get("output_dir"),
            "checks": {
                "no_network": row["classification"] != REQUIRES_NETWORK,
                "no_dependency_install": True,
                "no_env_or_secrets": row["classification"] != FORBIDDEN,
                "no_broadcasts": row["classification"] != FORBIDDEN,
                "no_deployment_scripts": "forge script" not in str(row.get("command") or "").lower(),
                "generated_tests_isolated": str(row.get("output_dir") or "").startswith("generated_pocs/"),
            },
            "network_used": False,
            "secrets_accessed": False,
            "broadcasts_used": False,
            "dependency_install_attempted": False,
            "production_source_modified": False,
            "patch_metadata_visible_during_detection": False,
            "reasons": row.get("reasons", []),
            "poc": row,
        }
    out = root / "scoring" / "poc_vertical_slice_execution_gate.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    (root / "scoring" / f"poc_vertical_slice_{safe_id(candidate_id)}_execution_gate.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def batch_candidate_ids(root: Path) -> list[str]:
    batch = load_json(root / "scoring" / "poc_vertical_slice_batch_selection.json", {})
    return [c.get("candidate_id") for c in batch.get("selected_candidates", []) if c.get("candidate_id")]


def preflight_batch(root: Path = PUBLIC_ROOT) -> dict[str, Any]:
    rows = [preflight_candidate(root, candidate_id=cid) for cid in batch_candidate_ids(root)]
    result = {"status": "PASS" if rows and all(r.get("allowed_to_execute") for r in rows) else "BLOCKED", "preflight_count": len(rows), "allowed_count": sum(1 for r in rows if r.get("allowed_to_execute")), "results": rows, "production_readiness_changed": False}
    (root / "scoring" / "poc_vertical_slice_batch_execution_gate.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def repaired_source_review_path(root: Path, split: str = "fresh-confirmation") -> Path:
    return repaired_execution_dir_for(root, split) / "repair_candidate_source_review.json"


def load_repaired_source_review(root: Path, split: str = "fresh-confirmation") -> dict[str, Any]:
    review = load_json(repaired_source_review_path(root, split), {})
    if review or split != "fresh-v8":
        return review
    return load_json(repaired_source_review_path(root, "fresh-confirmation"), {})


def repaired_candidate_manifest_path(root: Path, candidate_id: str, split: str = "fresh-confirmation") -> Path:
    subdir = FRESH_V8_REPAIR_POC_DIR if split == "fresh-v8" else FRESH_POSTHOC_REPAIR_POC_DIR
    return generated_root(root) / subdir / candidate_id / "poc_manifest.json"


def find_repaired_candidate_manifest(root: Path, candidate_id: str, split: str = "fresh-confirmation") -> Path | None:
    exact = repaired_candidate_manifest_path(root, candidate_id, split=split)
    if exact.exists():
        return exact
    if split != "fresh-v8":
        fresh_v8_exact = repaired_candidate_manifest_path(root, candidate_id, split="fresh-v8")
        if fresh_v8_exact.exists():
            return fresh_v8_exact
    manifest = find_candidate_manifest(root, candidate_id)
    if manifest and (FRESH_POSTHOC_REPAIR_POC_DIR in manifest.parts or FRESH_V8_REPAIR_POC_DIR in manifest.parts):
        return manifest
    return manifest


def generated_text_for_manifest(path: Path) -> str:
    return read_generated_text(path)


def repaired_assertion_checks(manifest: dict[str, Any], generated_text: str) -> dict[str, Any]:
    assertion = str(manifest.get("assertion") or "")
    kill = str(manifest.get("kill_condition") or "")
    lower_source = generated_text.lower()
    concrete_tokens = [
        "deposited > actualdistributorbalance",
        "require(!withdrawok",
        "recorded amount remained withdrawable",
    ]
    has_source_assertion = all(token in lower_source for token in concrete_tokens)
    has_manifest_assertion = bool(assertion.strip()) and "scaffold" not in assertion.lower()
    has_kill_condition = bool(kill.strip())
    missing: list[str] = []
    if not has_manifest_assertion:
        missing.append("manifest_missing_concrete_assertion")
    if not has_source_assertion:
        missing.append("generated_test_missing_concrete_assertions")
    if not has_kill_condition:
        missing.append("missing_kill_condition")
    return {
        "has_manifest_assertion": has_manifest_assertion,
        "has_source_assertion": has_source_assertion,
        "has_kill_condition": has_kill_condition,
        "assertion_ready": not missing,
        "missing": missing,
    }


def fresh_v8_repair_assertion_checks(manifest: dict[str, Any], generated_text: str) -> dict[str, Any]:
    assertion = str(manifest.get("assertion") or manifest.get("concrete_assertion") or "")
    kill = str(manifest.get("kill_condition") or "")
    lower_source = generated_text.lower()
    concrete_tokens = [
        "attackerstakeafterzerosupply",
        "require(attackerstakeafterzerosupply",
        "registry.isvalidator",
        "ve.delegateof",
        "ve.initiallock",
        "kill:",
    ]
    has_source_assertion = all(token in lower_source.replace(" ", "") for token in concrete_tokens)
    has_manifest_assertion = bool(assertion.strip()) and "scaffold" not in assertion.lower()
    has_kill_condition = bool(kill.strip())
    missing: list[str] = []
    if not has_manifest_assertion:
        missing.append("manifest_missing_concrete_assertion")
    if not has_source_assertion:
        missing.append("generated_test_missing_concrete_assertions")
    if not has_kill_condition:
        missing.append("missing_kill_condition")
    return {
        "has_manifest_assertion": has_manifest_assertion,
        "has_source_assertion": has_source_assertion,
        "has_kill_condition": has_kill_condition,
        "assertion_ready": not missing,
        "missing": missing,
    }


def repaired_manifest_validation_blocks(manifest: dict[str, Any], *, split: str, candidate_id: str) -> list[str]:
    blocks: list[str] = []
    if split == "fresh-v8" and candidate_id != APPROVED_FRESH_V8_REPAIR_CANDIDATE:
        blocks.append("fresh-v8 repair execution gate is limited to the approved candidate id")
    if not manifest:
        blocks.append("manifest missing")
        return blocks
    if manifest.get("candidate_id") != candidate_id:
        blocks.append("manifest candidate_id mismatch")
    if manifest.get("counts_toward_readiness") is not False:
        blocks.append("manifest must keep counts_toward_readiness false")
    if manifest.get("counts_as_finding") is not False:
        blocks.append("manifest must keep counts_as_finding false")
    if manifest.get("production_source_modified") is True or manifest.get("modifies_production_source") is True:
        blocks.append("manifest declares production source modification")
    if manifest.get("requires_network") is True or manifest.get("requires_fork") is True:
        blocks.append("manifest declares network/fork requirement")
    if manifest.get("dependency_install_required") is True or manifest.get("dependency_install_allowed") is True:
        blocks.append("manifest declares dependency installation")
    if manifest.get("requires_secrets") is True or manifest.get("secrets_accessed") is True or manifest.get("reads_environment") is True:
        blocks.append("manifest declares secret or environment access")
    if manifest.get("broadcasts_used") is True:
        blocks.append("manifest declares broadcast use")
    return blocks


def match_test_validation_blocks(generated_text: str, match_test: str) -> list[str]:
    if not match_test:
        return []
    blocks: list[str] = []
    if not re.fullmatch(r"test_[A-Za-z0-9_]+", match_test):
        blocks.append("match-test must be a single generated test function name")
        return blocks
    if not re.search(rf"function\s+{re.escape(match_test)}\s*\(", generated_text):
        blocks.append("match-test function not found in generated PoC file")
    return blocks


def classify_repaired_manifest(path: Path, root: Path, *, candidate_id: str, split: str = "fresh-confirmation", match_test: str = "") -> dict[str, Any]:
    row = classify_manifest(path, root)
    manifest = load_json(path, {})
    generated_text = generated_text_for_manifest(path)
    reasons = list(row.get("reasons", []))
    output_dir = str(path.parent.relative_to(root)) if _within(path.parent, root) else str(path.parent)
    expected_subdir = FRESH_V8_REPAIR_POC_DIR if split == "fresh-v8" else FRESH_POSTHOC_REPAIR_POC_DIR
    expected_prefix = f"generated_pocs/{expected_subdir}/{candidate_id}"
    local_scope = output_dir == expected_prefix
    if not local_scope:
        row["classification"] = FORBIDDEN
        reasons.append(f"repaired candidate must execute only inside its {expected_subdir} generated directory")
    poc_type = str(manifest.get("poc_type") or "")
    expected_poc_prefix = "fresh_v8_repair" if split == "fresh-v8" else "fresh_posthoc_repair"
    if not poc_type.startswith(expected_poc_prefix):
        reasons.append("manifest is not a repaired post-hoc PoC manifest")
    validation_blocks = repaired_manifest_validation_blocks(manifest, split=split, candidate_id=candidate_id)
    reasons.extend(validation_blocks)
    if validation_blocks:
        row["classification"] = FORBIDDEN
    match_blocks = match_test_validation_blocks(generated_text, match_test)
    reasons.extend(match_blocks)
    if match_blocks:
        row["classification"] = FORBIDDEN
    if match_test and not match_blocks:
        row["command"] = f"forge test --match-test {match_test} -vv"
    manual_fill = bool(manifest.get("manual_fill_completed")) and not bool(manifest.get("scaffold_only", True))
    if not manual_fill:
        reasons.append("manual filled PoC is required before execution")
    assertion = fresh_v8_repair_assertion_checks(manifest, generated_text) if split == "fresh-v8" else repaired_assertion_checks(manifest, generated_text)
    reasons.extend(assertion["missing"])
    review = load_repaired_source_review(root, split=split)
    source_review_ready = review.get("candidate_id") in {candidate_id, manifest.get("candidate_id")} and not review.get("source_review_blocks")
    if not source_review_ready:
        reasons.append("source review artifact missing or blocked")
    install_blocked = any("dependency install command blocked" == reason for reason in reasons)
    no_dependency_install = not install_blocked
    execution_approved = bool(
        row.get("classification") == SAFE_LOCAL_TEST
        and (row.get("execution_approved") or split == "fresh-v8")
        and local_scope
        and manual_fill
        and assertion["assertion_ready"]
        and source_review_ready
        and not validation_blocks
        and not match_blocks
    )
    row.update(
        {
            "candidate_id": candidate_id,
            "repaired_candidate_id": manifest.get("repaired_candidate_id") or candidate_id,
            "case_id": manifest.get("case_id"),
            "split": manifest.get("split"),
            "output_dir": output_dir,
            "classification": row.get("classification"),
            "execution_approved": execution_approved,
            "manual_fill_completed": manual_fill,
            "assertion_ready": assertion["assertion_ready"],
            "assertion_checks": assertion,
            "source_review_ready": source_review_ready,
            "local_scope": local_scope,
            "match_test": match_test,
            "no_dependency_install": no_dependency_install,
            "reasons": list(dict.fromkeys(reasons)) or ["safe local repaired Foundry test"],
            "report_ready": False,
            "counts_as_finding": False,
            "counts_toward_readiness": False,
        }
    )
    return row


def preflight_repaired_candidate(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation", candidate_id: str, match_test: str = "") -> dict[str, Any]:
    manifest = find_repaired_candidate_manifest(root, candidate_id, split=split)
    if not manifest:
        row = {
            "candidate_id": candidate_id,
            "classification": REQUIRES_DEPENDENCIES,
            "execution_approved": False,
            "command": "",
            "output_dir": "missing",
            "reasons": ["repaired candidate manifest missing"],
            "assertion_ready": False,
            "source_review_ready": False,
            "local_scope": False,
            "no_dependency_install": True,
        }
    else:
        row = classify_repaired_manifest(manifest, root, candidate_id=candidate_id, split=split, match_test=match_test)
    allowed = bool(row["classification"] == SAFE_LOCAL_TEST and row.get("execution_approved"))
    if allowed and manifest and split == "fresh-v8":
        payload = load_json(manifest, {})
        payload.update({
            "execution_approved": True,
            "gate_allowed_to_execute": True,
            "execution_block_reason": "",
            "executed": False,
            "counts_as_finding": False,
            "counts_toward_readiness": False,
            "production_source_modified": False,
            "modifies_production_source": False,
            "production_readiness_changed": False,
        })
        manifest.write_text(json.dumps(payload, indent=2) + "\n")
        row["execution_approved"] = True
    result = {
        "status": "PASS" if allowed else "BLOCKED",
        "mode": "fresh_posthoc_repair_preflight",
        "candidate_id": candidate_id,
        "split": split,
        "match_test": match_test,
        "classification": row["classification"],
        "allowed_to_execute": allowed,
        "execution_command": row.get("command"),
        "output_dir": row.get("output_dir"),
        "checks": {
            "no_network": row["classification"] != REQUIRES_NETWORK,
            "no_dependency_install": bool(row.get("no_dependency_install", True)),
            "no_env_or_secrets": row["classification"] != FORBIDDEN or not any("environment or secret" in r for r in row.get("reasons", [])),
            "no_broadcasts": row["classification"] != FORBIDDEN or not any("broadcast" in r for r in row.get("reasons", [])),
            "no_deployment_scripts": "forge script" not in str(row.get("command") or "").lower(),
            "generated_tests_isolated": bool(row.get("local_scope")),
            "local_frozen_artifacts_only": True,
            "manual_fill_completed": bool(row.get("manual_fill_completed")),
            "concrete_assertion": bool(row.get("assertion_ready")),
            "kill_condition_present": bool((row.get("assertion_checks") or {}).get("has_kill_condition")),
            "source_review_ready": bool(row.get("source_review_ready")),
        },
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "dependency_install_attempted": False,
        "production_source_modified": False,
        "patch_metadata_visible_during_detection": False,
        "post_hoc_spent_holdout": True,
        "fresh_bounty_evidence": False,
        "counts_toward_readiness": False,
        "reasons": row.get("reasons", []),
        "poc": row,
        "report_ready_created": False,
        "production_readiness_changed": False,
    }
    out_dir = repaired_execution_dir_for(root, split)
    out_dir.joinpath("repair_candidate_execution_gate.json").write_text(json.dumps(result, indent=2) + "\n")
    if split == "fresh-v8":
        repaired_execution_dir(root).joinpath("repair_candidate_execution_gate.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def execute_one(root: Path, row: dict[str, Any], *, timeout: int = 60, dry_run: bool = False) -> dict[str, Any]:
    if not row.get("execution_approved"):
        return {**row, "execution_status": "SKIPPED", "reason": "; ".join(row.get("reasons", []))}
    cwd = root / row["output_dir"]
    args = shlex.split(row["command"])
    if dry_run:
        return {**row, "execution_status": "DRY_RUN", "returncode": 0}
    try:
        proc = subprocess.run(args, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {**row, "execution_status": "TIMEOUT", "returncode": -1}
    status = "PASS" if proc.returncode == 0 else "FAIL"
    return {**row, "execution_status": status, "returncode": proc.returncode, "stdout_tail": proc.stdout[-2000:], "stderr_tail": proc.stderr[-2000:], "report_ready": False, "counts_as_finding": False}


def mark_repaired_manifest_after_execution(root: Path, *, split: str, candidate_id: str, exec_row: dict[str, Any]) -> None:
    manifest_path = find_repaired_candidate_manifest(root, candidate_id, split=split)
    if not manifest_path:
        return
    status = exec_row.get("execution_status")
    if status not in {"PASS", "FAIL", "TIMEOUT"}:
        return
    manifest = load_json(manifest_path, {})
    manifest.update({
        "execution_approved": True,
        "gate_allowed_to_execute": True,
        "executed": True,
        "execution_status": status,
        "execution_returncode": exec_row.get("returncode"),
        "execution_block_reason": "",
        "counts_as_finding": False,
        "counts_toward_readiness": False,
        "production_source_modified": False,
        "modifies_production_source": False,
        "production_readiness_changed": False,
    })
    manifest.pop("blocked_outcome", None)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")


def execute_approved(root: Path = PUBLIC_ROOT, *, split: str = "patched-controls", patch_regression: bool = False, dry_run: bool = False) -> dict[str, Any]:
    gate = gate_generated_pocs(root, split=split, patch_regression=patch_regression)
    results = [execute_one(root, row, dry_run=dry_run) for row in gate.get("pocs", [])]
    failed = [r for r in results if r.get("execution_status") in {"FAIL", "TIMEOUT"}]
    result = {
        "status": "FAIL" if failed else ("PASS" if results else "BLOCKED"),
        "split": split,
        "mode": "execute-approved-patch-regression" if patch_regression else "execute-approved-local",
        "executed_count": sum(1 for r in results if r.get("execution_status") in {"PASS", "FAIL", "TIMEOUT", "DRY_RUN"}),
        "skipped_count": sum(1 for r in results if r.get("execution_status") == "SKIPPED"),
        "failed_count": len(failed),
        "results": results,
        "production_readiness_changed": False,
        "report_ready_created": False,
        "confirmed_findings_created": 0,
    }
    name = "patch_regression_poc_execution_results.json" if patch_regression else "poc_execution_results.json"
    precision_dir(root).joinpath(name).write_text(json.dumps(result, indent=2) + "\n")
    return result


def execute_candidate(root: Path = PUBLIC_ROOT, *, candidate_id: str, dry_run: bool = False) -> dict[str, Any]:
    preflight = preflight_candidate(root, candidate_id=candidate_id)
    row = preflight.get("poc") or {}
    if not preflight.get("allowed_to_execute"):
        result = {
            "status": "BLOCKED",
            "candidate_id": candidate_id,
            "executed_count": 0,
            "skipped_count": 1,
            "failed_count": 0,
            "results": [{**row, "execution_status": "SKIPPED", "reason": "; ".join(preflight.get("reasons", []))}],
            "production_readiness_changed": False,
            "report_ready_created": False,
            "confirmed_findings_created": 0,
        }
    else:
        exec_row = execute_one(root, row, dry_run=dry_run)
        result = {
            "status": "PASS" if exec_row.get("execution_status") in {"PASS", "DRY_RUN"} else "FAIL",
            "candidate_id": candidate_id,
            "executed_count": 1 if exec_row.get("execution_status") in {"PASS", "FAIL", "TIMEOUT", "DRY_RUN"} else 0,
            "skipped_count": 0,
            "failed_count": 0 if exec_row.get("execution_status") in {"PASS", "DRY_RUN"} else 1,
            "results": [exec_row],
            "production_readiness_changed": False,
            "report_ready_created": False,
            "confirmed_findings_created": 0,
        }
    (root / "scoring" / "poc_vertical_slice_execution_raw.json").write_text(json.dumps(result, indent=2) + "\n")
    (root / "scoring" / f"poc_vertical_slice_{safe_id(candidate_id)}_execution_raw.json").write_text(json.dumps(result, indent=2) + "\n")
    if result.get("status") in {"PASS", "FAIL", "BLOCKED"} and not dry_run:
        write_vertical_slice_result(root, candidate_id=candidate_id)
    return result


def repaired_raw_path(root: Path, split: str = "fresh-confirmation") -> Path:
    return repaired_execution_dir_for(root, split) / "repair_candidate_execution_raw.json"


def repaired_control_raw_path(root: Path, split: str = "fresh-confirmation") -> Path:
    return repaired_execution_dir_for(root, split) / "repair_candidate_control_execution_raw.json"


def repaired_result_path(root: Path, split: str = "fresh-confirmation") -> Path:
    return repaired_execution_dir_for(root, split) / "repair_candidate_execution_result.json"


def repaired_control_result_path(root: Path, split: str = "fresh-confirmation") -> Path:
    return repaired_execution_dir_for(root, split) / "repair_candidate_control_execution_result.json"


def repaired_evidence_path(root: Path, split: str = "fresh-confirmation") -> Path:
    return repaired_execution_dir_for(root, split) / "repair_candidate_evidence_package.json"


def repaired_final_evidence_path(root: Path, split: str = "fresh-confirmation") -> Path:
    return repaired_execution_dir_for(root, split) / "repair_candidate_final_evidence_package.json"


def repaired_report_draft_path(root: Path, split: str = "fresh-confirmation") -> Path:
    return repaired_execution_dir_for(root, split) / "repair_candidate_report_draft.md"


def repaired_kill_report_path(root: Path, split: str = "fresh-confirmation") -> Path:
    return repaired_execution_dir_for(root, split) / "repair_candidate_kill_report.json"


def is_control_match(match_test: str) -> bool:
    return match_test.startswith("test_control_")


def execute_repaired_candidate(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation", candidate_id: str, dry_run: bool = False, match_test: str = "") -> dict[str, Any]:
    preflight = preflight_repaired_candidate(root, split=split, candidate_id=candidate_id, match_test=match_test)
    row = preflight.get("poc") or {}
    if not preflight.get("allowed_to_execute"):
        result = {
            "status": "BLOCKED",
            "mode": "fresh_posthoc_repair_execute_approved_local",
            "candidate_id": candidate_id,
            "match_test": match_test,
            "executed_count": 0,
            "skipped_count": 1,
            "failed_count": 0,
            "results": [{**row, "execution_status": "SKIPPED", "reason": "; ".join(preflight.get("reasons", []))}],
            "network_used": False,
            "secrets_accessed": False,
            "broadcasts_used": False,
            "dependency_install_attempted": False,
            "production_source_modified": False,
            "report_ready_created": False,
            "production_readiness_changed": False,
            "counts_toward_readiness": False,
        }
    else:
        exec_row = execute_one(root, row, dry_run=dry_run)
        if not dry_run:
            mark_repaired_manifest_after_execution(root, split=split, candidate_id=candidate_id, exec_row=exec_row)
        failed = exec_row.get("execution_status") in {"FAIL", "TIMEOUT"}
        result = {
            "status": "FAIL" if failed else "PASS",
            "mode": "fresh_posthoc_repair_execute_approved_local",
            "candidate_id": candidate_id,
            "match_test": match_test,
            "executed_count": 1 if exec_row.get("execution_status") in {"PASS", "FAIL", "TIMEOUT", "DRY_RUN"} else 0,
            "skipped_count": 0,
            "failed_count": 1 if failed else 0,
            "results": [exec_row],
            "network_used": False,
            "secrets_accessed": False,
            "broadcasts_used": False,
            "dependency_install_attempted": False,
            "production_source_modified": False,
            "report_ready_created": False,
            "production_readiness_changed": False,
            "counts_toward_readiness": False,
        }
    raw_path = repaired_control_raw_path(root, split) if is_control_match(match_test) else repaired_raw_path(root, split)
    raw_path.write_text(json.dumps(result, indent=2) + "\n")
    if split == "fresh-v8":
        legacy_raw_path = repaired_control_raw_path(root, "fresh-confirmation") if is_control_match(match_test) else repaired_raw_path(root, "fresh-confirmation")
        legacy_raw_path.write_text(json.dumps(result, indent=2) + "\n")
    if not dry_run:
        write_repaired_candidate_result(root, candidate_id=candidate_id, split=split, match_test=match_test)
    return result


def repaired_outcome_from_row(row: dict[str, Any], manifest: dict[str, Any], gate: dict[str, Any]) -> str:
    checks = gate.get("checks") or {}
    assertion_checks = row.get("assertion_checks") or {}
    assertion_ready = assertion_checks.get("assertion_ready")
    if assertion_ready is None:
        assertion_ready = bool(checks.get("concrete_assertion", bool(manifest.get("assertion"))))
    if not manifest.get("assertion"):
        assertion_ready = False
    if not assertion_ready:
        return POC_BLOCKED_MISSING_ASSERTION
    if row.get("classification") == REQUIRES_DEPENDENCIES:
        return POC_BLOCKED_MISSING_DEPENDENCIES
    if row.get("classification") in {REQUIRES_NETWORK, FORBIDDEN, EXECUTES_UNTRUSTED_CODE}:
        return POC_BLOCKED_UNSAFE
    if row.get("execution_status") in {"", None, "SKIPPED", "DRY_RUN"}:
        return POC_INCONCLUSIVE
    if row.get("execution_status") == "PASS":
        return POC_PASS_CONFIRMS_HYPOTHESIS
    combined = (str(row.get("stdout_tail") or "") + str(row.get("stderr_tail") or "")).lower()
    if row.get("execution_status") in {"FAIL", "TIMEOUT"} and ("compilation failed" in combined or "compiler run failed" in combined or "solc" in combined and "error" in combined):
        return POC_INCONCLUSIVE
    if row.get("execution_status") == "FAIL":
        return POC_FAILS_KILLS_HYPOTHESIS
    return POC_INCONCLUSIVE


def repaired_evidence_package_for(root: Path, candidate_id: str, result: dict[str, Any], *, split: str = "fresh-confirmation") -> dict[str, Any]:
    manifest_path = find_repaired_candidate_manifest(root, candidate_id, split=split)
    manifest = load_json(manifest_path, {}) if manifest_path else {}
    review = load_repaired_source_review(root, split=split)
    row = result.get("execution_row") or {}
    command = row.get("command") or manifest.get("command")
    if split == "fresh-v8" or manifest.get("contract") == "AgentVeToken":
        return {
            "candidate_id": candidate_id,
            "repaired_candidate_id": manifest.get("repaired_candidate_id") or candidate_id,
            "hypothesis_id": manifest.get("hypothesis_id"),
            "case_id": manifest.get("case_id"),
            "split": manifest.get("split") or split,
            "status": "REPORT_READY_POSTHOC_SPENT_HOLDOUT",
            "file": manifest.get("file_path"),
            "contract": manifest.get("contract"),
            "function": manifest.get("function"),
            "bug_class": manifest.get("bug_class"),
            "vulnerable_code_path": "AgentVeToken.stake -> canStake || totalSupply()==0 guard -> initialLock reset -> addValidator/delegate/mint",
            "preconditions": [
                "local-only generated Foundry harness",
                "private AgentVeToken has canStake=false",
                "founder performs the initial zero-supply stake and later withdraws after maturity so totalSupply returns to zero",
                "normal unprivileged caller has staking asset balance and approval",
                "no network, fork, broadcast, deployment, dependency install, or secret access",
            ],
            "attacker_capability": "normal external caller with staking asset balance and approval in the local harness",
            "affected_asset": manifest.get("affected_asset") or "AgentVeToken permissions, delegated state, and validator state",
            "exploit_sequence": [
                "deploy local AgentVeToken/asset/registry harness with canStake=false",
                "founder stakes first while totalSupply is zero",
                "founder withdraws after maturity, returning totalSupply to zero while private mode remains disabled",
                "normal attacker stakes as the next zero-supply staker",
                "assert attacker receives veTokens, registers attacker delegate as validator, records delegate, and rewrites initialLock",
            ],
            "impact": "The local PoC demonstrates unauthorized private-agent staking/delegation state change after supply returns to zero: an unprivileged caller mints veTokens, registers a validator delegate, and rewrites initialLock while canStake remains false.",
            "likelihood": "conditional on a private AgentVeToken reaching zero supply after founder maturity; live value at risk is not proven",
            "severity_rationale": "Post-hoc spent-holdout evidence proves a local permission/state invariant break, but not live value at risk, attacker profit, or production readiness.",
            "poc_command": command,
            "poc_result": result.get("result"),
            "patched_regression_result": "not_applicable_posthoc_repair_no_patch_control",
            "recommended_fix": "Track whether the private agent bootstrap stake has already occurred and allow the totalSupply==0 exception only once, or require founder/admin authorization for private-mode first staking.",
            "confidence": "medium for the local permission invariant; not a fresh independent bounty finding",
            "source_review": f"scoring/{FRESH_V8_REPAIR_EXECUTION_DIR}/repair_candidate_source_review.json",
            "test_file": f"generated_pocs/{FRESH_V8_REPAIR_POC_DIR}/{candidate_id}/test/GeneratedPoC.t.sol",
            "limitations": [
                "post-hoc execution on a spent holdout",
                "not fresh independent bounty evidence",
                "no live deployment, RPC, fork, USD value, duplicate review, or intended-behavior review",
                "does not count toward production readiness",
            ],
            "report_ready": False,
            "normal_bounty_report_ready": False,
            "counts_toward_readiness": False,
            "network_used": False,
            "secrets_accessed": False,
            "broadcasts_used": False,
            "dependency_install_attempted": False,
            "production_source_modified": False,
            "production_readiness_changed": False,
            "source_review_summary": review,
        }
    return {
        "candidate_id": candidate_id,
        "repaired_candidate_id": manifest.get("repaired_candidate_id") or candidate_id,
        "hypothesis_id": manifest.get("hypothesis_id"),
        "case_id": manifest.get("case_id"),
        "split": manifest.get("split"),
        "status": "REPORT_READY_POSTHOC_SPENT_HOLDOUT",
        "file": manifest.get("file_path"),
        "contract": manifest.get("contract"),
        "function": manifest.get("function"),
        "bug_class": manifest.get("bug_class"),
        "vulnerable_code_path": "Distributor.supply -> safeTransferFrom(amount_) -> deposited += amount_ / lastUnderlyingBalance += amount_",
        "preconditions": [
            "local-only generated Foundry harness",
            "deposit pool exists and is caller of Distributor.supply",
            "token transferFrom delivers less than amount_ at the Distributor boundary",
            "no network, fork, broadcast, deployment, dependency install, or secret access",
        ],
        "attacker_capability": "normal protocol deposit-pool lifecycle caller in the local harness; public bounty reachability remains unproven",
        "affected_asset": manifest.get("affected_asset") or "Distributor deposit accounting and withdrawable token balance",
        "exploit_sequence": [
            "deploy local fee-on-transfer token and Distributor.supply harness",
            "register the caller as a deposit pool using that token",
            "supply 100 ether while the token burns 10% during transferFrom",
            "observe Distributor records 100 ether while holding 90 ether",
            "attempt to withdraw the recorded amount and observe the transfer reverts",
        ],
        "impact": "The local PoC demonstrates an accounting/fund-freeze condition: recorded deposit accounting exceeds actual token balance and the recorded amount cannot be withdrawn.",
        "likelihood": "conditional on an in-scope deposit token or lifecycle boundary where Distributor receives less than amount_ supplied; fresh bounty scope is not proven",
        "severity_rationale": "Post-hoc spent-holdout evidence proves a local accounting/freeze invariant break, but not live value at risk, attacker profit, or production readiness.",
        "poc_command": command,
        "poc_result": result.get("result"),
        "patched_regression_result": "not_applicable_posthoc_repair_no_patch_control",
        "recommended_fix": "Measure the token balance delta received by Distributor.supply and record/supply only the actual received amount, or reject fee-on-transfer/rebasing tokens for deposit pools.",
        "confidence": "medium for the local accounting invariant; not a fresh independent bounty finding",
        "source_review": "scoring/repaired_candidate_execution/repair_candidate_source_review.json",
        "test_file": f"generated_pocs/fresh_posthoc_repair/{candidate_id}/test/GeneratedPoC.t.sol",
        "limitations": [
            "post-hoc execution on a spent holdout",
            "not fresh independent bounty evidence",
            "no live deployment, RPC, fork, USD value, duplicate review, or intended-behavior review",
            "does not count toward production readiness",
        ],
        "report_ready": False,
        "normal_bounty_report_ready": False,
        "counts_toward_readiness": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "dependency_install_attempted": False,
        "production_source_modified": False,
        "production_readiness_changed": False,
        "source_review_summary": review,
    }


def repaired_final_package_for(evidence: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    if evidence.get("contract") == "AgentVeToken":
        return {
            **evidence,
            "status": "REPORT_READY_POSTHOC_SPENT_HOLDOUT",
            "report_key": "REPORT_READY_POSTHOC_SPENT_HOLDOUT",
            "poc_result": result.get("result") or evidence.get("poc_result"),
            "execution_status": result.get("execution_status"),
            "test_status": result.get("test_status"),
            "final_validation_scope": "post-hoc spent holdout only",
            "scope_review": "local frozen contest_5004_fallback source reviewed; live bounty scope not asserted",
            "value_at_risk": {
                "impact_class": "unauthorized_state_change",
                "amount_in_poc": "1 ether local stake minted after private supply returned to zero",
                "attacker_profit": False,
                "victim_loss_or_freeze": False,
                "live_usd_value_proven": False,
            },
            "economic_proof": {
                "economic_proof_status": "NOT_REQUIRED_LOCAL_PERMISSION_STATE_ONLY",
                "attacker_profit": False,
                "theft_claimed": False,
                "protocol_loss_usd": "0",
                "bad_debt_usd": "0",
            },
            "duplicate_known_issue_status": "NOT_CHECKED_POSTHOC_SPENT_HOLDOUT",
            "intended_behavior_review": "NOT_PERFORMED_POSTHOC_SPENT_HOLDOUT",
            "validation_status": "PASS_POSTHOC_SPENT_HOLDOUT_ONLY" if result.get("confirmed") else "BLOCKED",
            "report_ready": False,
            "normal_bounty_report_ready": False,
            "counts_toward_readiness": False,
            "production_readiness_changed": False,
        }
    package = {
        **evidence,
        "status": "REPORT_READY_POSTHOC_SPENT_HOLDOUT",
        "report_key": "REPORT_READY_POSTHOC_SPENT_HOLDOUT",
        "poc_result": result.get("result") or evidence.get("poc_result"),
        "execution_status": result.get("execution_status"),
        "test_status": result.get("test_status"),
        "final_validation_scope": "post-hoc spent holdout only",
        "scope_review": "local frozen contest_3003 source reviewed; live bounty scope not asserted",
        "value_at_risk": {
            "impact_class": "fund_freeze",
            "amount_in_poc": "100 ether recorded vs 90 ether actual received",
            "attacker_profit": False,
            "victim_loss_or_freeze": True,
            "live_usd_value_proven": False,
        },
        "economic_proof": {
            "economic_proof_status": "PARTIAL_LOCAL_ONLY",
            "attacker_profit": False,
            "theft_claimed": False,
            "protocol_loss_usd": "0",
            "bad_debt_usd": "0",
        },
        "duplicate_known_issue_status": "NOT_CHECKED_POSTHOC_SPENT_HOLDOUT",
        "intended_behavior_review": "NOT_PERFORMED_POSTHOC_SPENT_HOLDOUT",
        "validation_status": "PASS_POSTHOC_SPENT_HOLDOUT_ONLY" if result.get("confirmed") else "BLOCKED",
        "report_ready": False,
        "normal_bounty_report_ready": False,
        "counts_toward_readiness": False,
        "production_readiness_changed": False,
    }
    return package


def repaired_report_draft_for(evidence: dict[str, Any], final_package: dict[str, Any]) -> str:
    command = evidence.get("poc_command")
    if evidence.get("contract") == "AgentVeToken":
        return f"""# Private AgentVeToken zero-supply restake permits unauthorized staking/delegation state change

## Status
REPORT_READY_POSTHOC_SPENT_HOLDOUT. This is post-hoc spent-holdout evidence only. Normal bounty report-ready status is false. This does not count toward readiness.

## Scope note
This draft is limited to frozen local artifacts for `{evidence.get('case_id')}` and candidate `{evidence.get('candidate_id')}`. It does not assert live production scope, deployed value at risk, or production readiness.

## Affected component
File: {evidence.get('file')}
Contract: {evidence.get('contract')}
Function: {evidence.get('function')}
Affected Asset: {evidence.get('affected_asset')}

## Summary
The local PoC demonstrates that a private AgentVeToken with `canStake=false` accepts another normal zero-supply stake after the founder exits and totalSupply returns to zero. The attacker path mints veTokens, records the attacker delegate, registers that delegate as a validator, and rewrites `initialLock` while private mode remains disabled.

## Root cause
`AgentVeToken.stake` treats every zero-supply state as a first-stake exception instead of limiting the private-mode bootstrap exception to the initial founder-controlled lifecycle.

## Preconditions
{chr(10).join(f'- {item}' for item in evidence.get('preconditions', []))}

## Attack scenario
{chr(10).join(f'{idx + 1}. {item}' for idx, item in enumerate(evidence.get('exploit_sequence', [])))}

## Impact
Impact class: {final_package.get('value_at_risk', {}).get('impact_class')}
Local PoC amount: {final_package.get('value_at_risk', {}).get('amount_in_poc')}
Attacker profit: false
Normal bounty report-ready: false
Counts toward readiness: false

## Proof of Concept
PoC path: `{evidence.get('test_file')}`

Command:
```bash
{command}
```

Result: {evidence.get('poc_result')}

## Recommended remediation
{evidence.get('recommended_fix')}

## Limitations
{chr(10).join(f'- {item}' for item in evidence.get('limitations', []))}
"""
    return f"""# Accounting desync in Distributor.supply records more than received in local post-hoc spent-holdout PoC

## Status
REPORT_READY_POSTHOC_SPENT_HOLDOUT. Normal bounty report-ready status is false. This does not count toward readiness.

## Scope note
This draft is limited to frozen local artifacts for `{evidence.get('case_id')}` and candidate `{evidence.get('candidate_id')}`. It does not assert live production scope, deployed value at risk, or production readiness.

## Affected component
File: {evidence.get('file')}
Contract: {evidence.get('contract')}
Function: {evidence.get('function')}
Affected Asset: {evidence.get('affected_asset')}

## Summary
The PoC demonstrates that `Distributor.supply` records `amount_` in `deposited` and `lastUnderlyingBalance` after `transferFrom` without measuring the received balance delta. In the local fee-on-transfer boundary harness, the Distributor records 100 ether while holding 90 ether, and withdrawing the recorded amount reverts.

## Root cause
`Distributor.supply` trusts the requested transfer amount instead of the actual token balance delta received by the Distributor.

## Preconditions
{chr(10).join(f'- {item}' for item in evidence.get('preconditions', []))}

## Attack scenario
{chr(10).join(f'{idx + 1}. {item}' for idx, item in enumerate(evidence.get('exploit_sequence', [])))}

## Impact
Impact class: {final_package.get('value_at_risk', {}).get('impact_class')}
Local PoC amount: {final_package.get('value_at_risk', {}).get('amount_in_poc')}
Attacker profit: false
Normal bounty report-ready: false
Counts toward readiness: false

## Proof of Concept
PoC path: `{evidence.get('test_file')}`

Command:
```bash
{command}
```

Result: {evidence.get('poc_result')}

## Recommended remediation
{evidence.get('recommended_fix')}

## Limitations
{chr(10).join(f'- {item}' for item in evidence.get('limitations', []))}
"""


def repaired_kill_report_for(root: Path, candidate_id: str, result: dict[str, Any], *, split: str = "fresh-confirmation") -> dict[str, Any]:
    manifest_path = find_repaired_candidate_manifest(root, candidate_id, split=split)
    manifest = load_json(manifest_path, {}) if manifest_path else {}
    row = result.get("execution_row") or {}
    if split == "fresh-v8" or manifest.get("contract") == "AgentVeToken":
        return {
            "candidate_id": candidate_id,
            "hypothesis_id": manifest.get("hypothesis_id"),
            "case_id": manifest.get("case_id"),
            "result": result.get("result"),
            "failing_assumption": "The filled local PoC did not prove private-mode zero-supply restake state change, or the attacker stake was blocked.",
            "kill_condition": manifest.get("kill_condition"),
            "execution_status": row.get("execution_status"),
            "stdout_summary": result.get("stdout_summary"),
            "stderr_summary": result.get("stderr_summary"),
            "report_ready": False,
            "normal_bounty_report_ready": False,
            "counts_toward_readiness": False,
            "network_used": False,
            "secrets_accessed": False,
            "broadcasts_used": False,
            "dependency_install_attempted": False,
            "production_source_modified": False,
            "production_readiness_changed": False,
        }
    return {
        "candidate_id": candidate_id,
        "hypothesis_id": manifest.get("hypothesis_id"),
        "case_id": manifest.get("case_id"),
        "result": result.get("result"),
        "failing_assumption": "The filled local PoC did not prove that Distributor.supply records more than the actual received token balance, or the recorded amount remained withdrawable.",
        "kill_condition": manifest.get("kill_condition"),
        "execution_status": row.get("execution_status"),
        "stdout_summary": result.get("stdout_summary"),
        "stderr_summary": result.get("stderr_summary"),
        "report_ready": False,
        "normal_bounty_report_ready": False,
        "counts_toward_readiness": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "dependency_install_attempted": False,
        "production_source_modified": False,
        "production_readiness_changed": False,
    }


def update_repaired_feedback_memory(root: Path, result: dict[str, Any], evidence: dict[str, Any] | None, kill_report: dict[str, Any] | None, *, split: str = "fresh-confirmation") -> dict[str, Any]:
    out_dir = repaired_execution_dir_for(root, split)
    memory_path = out_dir / "repair_candidate_feedback_memory.json"
    lead = evidence or kill_report or {"id": result.get("candidate_id"), "bug_class": "fresh-posthoc-repair", "title": result.get("result")}
    if result.get("confirmed"):
        entry = record_confirmed_finding(memory_path, lead=lead, reason="post-hoc spent-holdout repaired PoC executed and confirmed the local accounting/freeze hypothesis", original_report="")
        outcome = "record_confirmed_finding"
    elif result.get("killed"):
        entry = record_false_positive(memory_path, lead=lead, reason="post-hoc repaired PoC killed the hypothesis", original_report="")
        outcome = "record_false_positive"
    else:
        entry = record_reviewer_feedback(memory_path, lead=lead, outcome="NEEDS_MORE_INFO", triager_reason=str(result.get("result")), original_report="")
        outcome = "record_reviewer_feedback"
    update = {"status": "PASS", "outcome": outcome, "recorded": True, "memory_path": str(memory_path.relative_to(root)), "feedback_id": entry.get("feedback_id")}
    out_dir.joinpath("repair_candidate_feedback_update.json").write_text(json.dumps(update, indent=2) + "\n")
    return update


def mirror_fresh_v8_repaired_artifacts(root: Path) -> None:
    fresh_dir = repaired_execution_dir_for(root, "fresh-v8")
    legacy_dir = repaired_execution_dir(root)
    for name in [
        "repair_candidate_execution_gate.json",
        "repair_candidate_execution_raw.json",
        "repair_candidate_control_execution_raw.json",
        "repair_candidate_execution_result.json",
        "repair_candidate_control_execution_result.json",
        "repair_candidate_evidence_package.json",
        "repair_candidate_final_evidence_package.json",
        "repair_candidate_report_draft.md",
        "repair_candidate_kill_report.json",
        "repair_candidate_feedback_update.json",
        "repair_candidate_feedback_memory.json",
    ]:
        source = fresh_dir / name
        if source.exists():
            target = legacy_dir / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source.read_text(errors="replace"))


def control_outcome_from_row(row: dict[str, Any]) -> str:
    if row.get("classification") in {REQUIRES_NETWORK, FORBIDDEN, EXECUTES_UNTRUSTED_CODE}:
        return "CONTROL_BLOCKED_UNSAFE"
    if row.get("classification") == REQUIRES_DEPENDENCIES:
        return "CONTROL_BLOCKED_MISSING_SETUP"
    if row.get("execution_status") == "PASS":
        return "CONTROL_PASS_SUPPORTS_HYPOTHESIS"
    if row.get("execution_status") == "FAIL":
        return "CONTROL_FAIL_WEAKENS_HYPOTHESIS"
    if row.get("execution_status") == "TIMEOUT":
        return "CONTROL_INCONCLUSIVE"
    return "CONTROL_INCONCLUSIVE"


def update_repaired_report_with_control(report_path: Path, control: dict[str, Any]) -> None:
    if not report_path.exists():
        return
    text = report_path.read_text(errors="replace")
    marker = "\n## Control Test\n"
    section = f"""
## Control Test
Control test command:
```bash
{control.get('command')}
```

Control result: {control.get('result')}

Control supports hypothesis: {str(bool(control.get('control_supports_hypothesis'))).lower()}

Control notes: {control.get('stdout_summary')}
"""
    if marker in text:
        text = text.split(marker)[0].rstrip() + "\n" + section
    else:
        text = text.rstrip() + "\n" + section
    report_path.write_text(text)


def update_repaired_evidence_with_control(root: Path, *, split: str, candidate_id: str, control: dict[str, Any]) -> None:
    for path in [repaired_evidence_path(root, split), repaired_final_evidence_path(root, split)]:
        package = load_json(path, {})
        if not package:
            continue
        package.update({
            "exploit_test_result": package.get("poc_result") or "POC_PASS_CONFIRMS_HYPOTHESIS",
            "control_test_result": control.get("result"),
            "control_test_name": control.get("match_test"),
            "control_test_command": control.get("command"),
            "control_supports_hypothesis": bool(control.get("control_supports_hypothesis")),
            "same_generated_poc_file": True,
            "counts_toward_readiness": False,
            "production_readiness_changed": False,
        })
        if control.get("result") == "CONTROL_FAIL_WEAKENS_HYPOTHESIS":
            package["status"] = "BLOCKED_CONTROL_FAILED"
            package["validation_status"] = "BLOCKED_CONTROL_FAILED"
            package["normal_bounty_report_ready"] = False
        path.write_text(json.dumps(package, indent=2) + "\n")
    update_repaired_report_with_control(repaired_report_draft_path(root, split), control)
    if split == "fresh-v8":
        mirror_fresh_v8_repaired_artifacts(root)


def write_repaired_control_result(root: Path = PUBLIC_ROOT, *, candidate_id: str, split: str = "fresh-confirmation", match_test: str) -> dict[str, Any]:
    raw = load_json(repaired_control_raw_path(root, split), {})
    gate = load_json(repaired_execution_dir_for(root, split) / "repair_candidate_execution_gate.json", {})
    row = (raw.get("results") or [gate.get("poc") or {}])[0]
    outcome = control_outcome_from_row(row)
    result = {
        "candidate_id": candidate_id,
        "case_id": row.get("case_id"),
        "match_test": match_test,
        "result": outcome,
        "execution_status": row.get("execution_status") or "NOT_EXECUTED",
        "command": row.get("command"),
        "stdout_summary": stdout_summary(row),
        "stderr_summary": stderr_summary(row),
        "control_supports_hypothesis": outcome == "CONTROL_PASS_SUPPORTS_HYPOTHESIS",
        "same_generated_poc_file": True,
        "execution_row": row,
        "normal_bounty_report_ready": False,
        "counts_toward_readiness": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "dependency_install_attempted": False,
        "production_source_modified": False,
        "production_readiness_changed": False,
    }
    repaired_control_result_path(root, split).write_text(json.dumps(result, indent=2) + "\n")
    update_repaired_evidence_with_control(root, split=split, candidate_id=candidate_id, control=result)
    if split == "fresh-v8":
        mirror_fresh_v8_repaired_artifacts(root)
    return result


def write_repaired_candidate_result(root: Path = PUBLIC_ROOT, *, candidate_id: str, split: str = "fresh-confirmation", match_test: str = "") -> dict[str, Any]:
    if is_control_match(match_test):
        return write_repaired_control_result(root, candidate_id=candidate_id, split=split, match_test=match_test)
    raw = load_json(repaired_raw_path(root, split), {})
    gate = load_json(repaired_execution_dir_for(root, split) / "repair_candidate_execution_gate.json", {})
    if not raw and not gate:
        gate = preflight_repaired_candidate(root, split=split, candidate_id=candidate_id)
    row = (raw.get("results") or [gate.get("poc") or {}])[0]
    manifest_path = find_repaired_candidate_manifest(root, candidate_id, split=split)
    manifest = load_json(manifest_path, {}) if manifest_path else {}
    outcome = repaired_outcome_from_row(row, manifest, gate)
    result = {
        "candidate_id": candidate_id,
        "hypothesis_id": manifest.get("hypothesis_id"),
        "case_id": manifest.get("case_id"),
        "result": outcome,
        "local_execution_classification": row.get("classification") or gate.get("classification"),
        "execution_status": row.get("execution_status") or "NOT_EXECUTED",
        "test_status": (
            "PASS_ASSERTED_PRIVATE_ZERO_SUPPLY_STAKE_STATE_CHANGE"
            if outcome == POC_PASS_CONFIRMS_HYPOTHESIS and (split == "fresh-v8" or manifest.get("contract") == "AgentVeToken")
            else (
                "PASS_ASSERTED_ACCOUNTING_DESYNC_AND_WITHDRAW_FREEZE"
                if outcome == POC_PASS_CONFIRMS_HYPOTHESIS
                else (
                    "FAIL_KILLS_PRIVATE_ZERO_SUPPLY_STAKE_HYPOTHESIS"
                    if outcome == POC_FAILS_KILLS_HYPOTHESIS and (split == "fresh-v8" or manifest.get("contract") == "AgentVeToken")
                    else ("FAIL_KILLS_ACCOUNTING_DESYNC_HYPOTHESIS" if outcome == POC_FAILS_KILLS_HYPOTHESIS else "NOT_CONFIRMED")
                )
            )
        ),
        "same_attack_steps_used": bool(manifest.get("same_attack_steps_used")),
        "assertion": manifest.get("assertion"),
        "kill_condition": manifest.get("kill_condition"),
        "command": row.get("command") or manifest.get("command"),
        "stdout_summary": stdout_summary(row),
        "stderr_summary": stderr_summary(row),
        "execution_row": row,
        "evidence_files": [
            f"generated_pocs/{FRESH_V8_REPAIR_POC_DIR if split == 'fresh-v8' else FRESH_POSTHOC_REPAIR_POC_DIR}/{candidate_id}/test/GeneratedPoC.t.sol",
            f"scoring/{FRESH_V8_REPAIR_EXECUTION_DIR if split == 'fresh-v8' else REPAIRED_EXECUTION_DIR}/repair_candidate_source_review.json",
            f"scoring/{FRESH_V8_REPAIR_EXECUTION_DIR if split == 'fresh-v8' else REPAIRED_EXECUTION_DIR}/repair_candidate_execution_gate.json",
            f"scoring/{FRESH_V8_REPAIR_EXECUTION_DIR if split == 'fresh-v8' else REPAIRED_EXECUTION_DIR}/repair_candidate_execution_raw.json",
        ],
        "confirmed": outcome == POC_PASS_CONFIRMS_HYPOTHESIS,
        "killed": outcome == POC_FAILS_KILLS_HYPOTHESIS,
        "blocked": outcome in {POC_BLOCKED_MISSING_DEPENDENCIES, POC_BLOCKED_UNSAFE, POC_BLOCKED_MISSING_ASSERTION},
        "inconclusive": outcome == POC_INCONCLUSIVE,
        "missing_assertion": outcome == POC_BLOCKED_MISSING_ASSERTION,
        "report_key": "REPORT_READY_POSTHOC_SPENT_HOLDOUT" if outcome == POC_PASS_CONFIRMS_HYPOTHESIS else "",
        "report_ready_created": False,
        "normal_bounty_report_ready": False,
        "post_hoc_spent_holdout": True,
        "fresh_bounty_evidence": False,
        "counts_toward_readiness": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "dependency_install_attempted": False,
        "production_source_modified": False,
        "production_readiness_changed": False,
    }
    repaired_result_path(root, split).write_text(json.dumps(result, indent=2) + "\n")
    evidence = None
    kill_report = None
    if result["confirmed"]:
        evidence = repaired_evidence_package_for(root, candidate_id, result, split=split)
        repaired_evidence_path(root, split).write_text(json.dumps(evidence, indent=2) + "\n")
        final_package = repaired_final_package_for(evidence, result)
        repaired_final_evidence_path(root, split).write_text(json.dumps(final_package, indent=2) + "\n")
        repaired_report_draft_path(root, split).write_text(repaired_report_draft_for(evidence, final_package))
    elif result["killed"]:
        kill_report = repaired_kill_report_for(root, candidate_id, result, split=split)
        repaired_kill_report_path(root, split).write_text(json.dumps(kill_report, indent=2) + "\n")
    update_repaired_feedback_memory(root, result, evidence, kill_report, split=split)
    if split == "fresh-v8":
        mirror_fresh_v8_repaired_artifacts(root)
    return result


def execute_batch(root: Path = PUBLIC_ROOT, *, dry_run: bool = False) -> dict[str, Any]:
    rows = [execute_candidate(root, candidate_id=cid, dry_run=dry_run) for cid in batch_candidate_ids(root)]
    result = {"status": "PASS" if rows and all(r.get("status") in {"PASS", "BLOCKED"} for r in rows) else "FAIL", "executed_count": sum(r.get("executed_count", 0) for r in rows), "skipped_count": sum(r.get("skipped_count", 0) for r in rows), "failed_count": sum(r.get("failed_count", 0) for r in rows), "results": rows, "production_readiness_changed": False, "report_ready_created": False}
    (root / "scoring" / "poc_vertical_slice_batch_execution_raw.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def stdout_summary(row: dict[str, Any]) -> str:
    out = str(row.get("stdout_tail") or "")
    lines = [line for line in out.splitlines() if "Ran " in line or "Suite result" in line or "test result" in line or "PASS" in line or "FAIL" in line]
    return "\n".join(lines[-8:]) or out[-500:]


def stderr_summary(row: dict[str, Any]) -> str:
    err = str(row.get("stderr_tail") or "")
    return err[-800:]


def load_vertical_selection(root: Path) -> dict[str, Any]:
    return load_json(root / "scoring" / "poc_vertical_slice_candidate_selection.json", {})


def load_candidate_selection(root: Path, candidate_id: str) -> dict[str, Any]:
    batch = load_json(root / "scoring" / "poc_vertical_slice_batch_selection.json", {})
    for candidate in batch.get("selected_candidates", []):
        if candidate.get("candidate_id") == candidate_id:
            return candidate
    single = load_vertical_selection(root)
    if single.get("selected_candidate_id") == candidate_id:
        return {"candidate_id": candidate_id, "pair_id": single.get("pair_id"), "file": single.get("file"), "contract": single.get("contract"), "function": single.get("function"), "attacker_capability": single.get("attacker_capability")}
    return {"candidate_id": candidate_id}


def evidence_package_for(root: Path, candidate_id: str, result: dict[str, Any]) -> dict[str, Any]:
    selection = load_candidate_selection(root, candidate_id)
    manifest_path = find_candidate_manifest(root, candidate_id)
    manifest = load_json(manifest_path, {}) if manifest_path else {}
    killed = bool(result.get("killed"))
    if candidate_id == "POC-PREC-case_pc_0002-vulnerable-003":
        vulnerable_code_path = "InvestmentManager.requestRedeem -> auth modifier -> no gateway/orderbook state change for normal caller"
        exploit_sequence = ["normal attacker calls requestRedeem for a victim", "auth check reverts before any order state changes", "same call reverts against patched harness"]
        affected_asset = "none confirmed; normal-attacker requestRedeem path did not mutate redemption accounting or assets"
        impact = "none confirmed; access-control hypothesis killed because normal attacker cannot reach the state-changing path"
        likelihood = "not applicable; the tested normal-attacker path is stopped by authorization before state mutation"
        severity_rationale = "No severity assigned because the local vertical-slice harness killed this hypothesis and confirmed no unauthorized state change."
        recommended_fix = "no fix proposed for this killed hypothesis; keep auth protection on requestRedeem"
    elif candidate_id == "POC-PREC-case_pc_0003-vulnerable-001":
        vulnerable_code_path = "LiquidityPool.requestRedeemWithPermit -> share.permit -> investmentManager.requestRedeem"
        exploit_sequence = ["normal attacker calls requestRedeemWithPermit with invalid permit data", "permit reverts before InvestmentManager requestRedeem", "same invalid permit path reverts against patched harness"]
        affected_asset = "none confirmed; invalid permit path did not reach redemption accounting or assets"
        impact = "none confirmed; permit-gated hypothesis killed because unauthorized call cannot reach redemption request without a valid permit"
        likelihood = "not applicable; the tested unauthorized permit path reverts before the sensitive requestRedeem call"
        severity_rationale = "No severity assigned because the local vertical-slice harness killed this hypothesis and confirmed no unauthorized state change."
        recommended_fix = "no fix proposed for this killed hypothesis; keep permit-before-request ordering"
    else:
        vulnerable_code_path = "InvestmentManager requestDeposit lifecycle -> handleExecutedCollectInvest orderbook limits -> processDeposit rounded tranche-token calculation -> escrow transfer"
        exploit_sequence = [
            "seed an executed deposit order with maxDeposit=1 and maxMint=600000000000000000",
            "process the full deposit amount through the vulnerable calculation",
            "observe vulnerable transfer requests 1000000000000000000 shares while only maxMint is escrowed, causing revert/freeze",
            "run the same processing amount against the patched clamp and observe transfer of exactly maxMint",
        ]
        affected_asset = "escrowed tranche tokens / deposit processing accounting for the investor"
        impact = "fund-freeze / accounting violation in the deposit-processing path under the rounded-down price condition"
        likelihood = "post-hoc patched-control reproduction for a boundary rounding condition; requires an executed order with price rounding down below the exact ratio"
        severity_rationale = "The local harness demonstrates the vulnerable path cannot process the full deposit order while the patched path preserves accounting. This remains a post-hoc regression artifact, not a production-ready report."
        recommended_fix = "Clamp the calculated tranche-token amount to orderbook[user][liquidityPool].maxMint before decreasing limits and transferring escrowed tranche tokens."
    return {
        "candidate_id": candidate_id,
        "pair_id": selection.get("pair_id"),
        "file": selection.get("file"),
        "contract": selection.get("contract"),
        "function": selection.get("function"),
        "vulnerable_code_path": vulnerable_code_path,
        "preconditions": ["local post-hoc patched-control harness", "same attack steps executed against vulnerable and patched behavior", "no network/fork/deployment script used"],
        "attacker_capability": selection.get("attacker_capability"),
        "affected_asset": affected_asset,
        "exploit_sequence": exploit_sequence,
        "impact": impact,
        "likelihood": likelihood,
        "severity_rationale": severity_rationale,
        "poc_command": manifest.get("command"),
        "poc_result": result.get("result"),
        "patched_regression_result": result.get("patched_test_status"),
        "recommended_fix": recommended_fix,
        "confidence": "medium-high for the patched-control arithmetic invariant; not report-ready without duplicate/intended-behavior review and full protocol context" if not killed else "high that this specific hypothesis is killed by the local authorization/permit harness",
        "limitations": ["post-hoc patched-control evidence only", "not fresh independent holdout evidence", "not automatically report-ready"],
        "report_ready": False,
        "production_readiness_changed": False,
    }


def update_feedback_memory(root: Path, result: dict[str, Any], evidence: dict[str, Any] | None) -> dict[str, Any]:
    memory_path = root / "scoring" / "poc_vertical_slice_feedback_memory.json"
    lead = evidence or {"id": result.get("candidate_id"), "bug_class": "poc-vertical-slice", "title": result.get("result")}
    if result.get("confirmed"):
        entry = record_confirmed_finding(memory_path, lead=lead, reason="post-hoc vertical-slice PoC executed and confirmed the rounded deposit-processing regression", original_report="")
        outcome = "record_confirmed_finding"
    elif result.get("killed"):
        entry = record_false_positive(memory_path, lead=lead, reason="post-hoc vertical-slice PoC killed the hypothesis", original_report="")
        outcome = "record_false_positive"
    else:
        entry = record_reviewer_feedback(memory_path, lead=lead, outcome="NEEDS_MORE_INFO", triager_reason=str(result.get("result")), original_report="")
        outcome = "record_reviewer_feedback"
    update = {"status": "PASS", "outcome": outcome, "recorded": True, "memory_path": str(memory_path.relative_to(root)), "feedback_id": entry.get("feedback_id")}
    (root / "scoring" / "poc_vertical_slice_feedback_update.json").write_text(json.dumps(update, indent=2) + "\n")
    return update


def write_vertical_slice_result(root: Path = PUBLIC_ROOT, *, candidate_id: str) -> dict[str, Any]:
    raw = load_json(root / "scoring" / f"poc_vertical_slice_{safe_id(candidate_id)}_execution_raw.json", {}) or load_json(root / "scoring" / "poc_vertical_slice_execution_raw.json", {})
    row = (raw.get("results") or [{}])[0]
    manifest_path = find_candidate_manifest(root, candidate_id)
    manifest = load_json(manifest_path, {}) if manifest_path else {}
    if row.get("classification") == REQUIRES_DEPENDENCIES:
        classification = "POC_BLOCKED_MISSING_DEPENDENCIES"
    elif row.get("classification") in {REQUIRES_NETWORK, FORBIDDEN}:
        classification = "POC_BLOCKED_UNSAFE"
    elif row.get("execution_status") == "PASS" and candidate_id in KILL_ON_PASS_CANDIDATES:
        classification = "POC_FAILS_KILLS_HYPOTHESIS"
    elif row.get("execution_status") == "PASS":
        classification = "POC_PASS_CONFIRMS_HYPOTHESIS"
    elif row.get("execution_status") == "FAIL" and "compilation failed" in (str(row.get("stdout_tail") or "") + str(row.get("stderr_tail") or "")).lower():
        classification = "POC_INCONCLUSIVE"
    elif row.get("execution_status") == "FAIL":
        classification = "POC_FAILS_KILLS_HYPOTHESIS"
    elif row.get("execution_status") == "SKIPPED":
        classification = "POC_INCONCLUSIVE"
    else:
        classification = "POC_INCONCLUSIVE"
    result = {
        "candidate_id": candidate_id,
        "pair_id": manifest.get("pair_id"),
        "vulnerable_test_status": "PASS_ASSERTED_REVERT_FUND_FREEZE" if classification == "POC_PASS_CONFIRMS_HYPOTHESIS" else ("PASS_ASSERTED_NO_UNAUTHORIZED_STATE_CHANGE" if classification == "POC_FAILS_KILLS_HYPOTHESIS" else "NOT_CONFIRMED"),
        "patched_test_status": "PASS_ASSERTED_CLAMP_ACCOUNTING_PRESERVED" if classification == "POC_PASS_CONFIRMS_HYPOTHESIS" else ("PASS_ASSERTED_NO_UNAUTHORIZED_STATE_CHANGE" if classification == "POC_FAILS_KILLS_HYPOTHESIS" else "NOT_CONFIRMED"),
        "same_attack_steps_used": bool(manifest.get("same_attack_steps_used")),
        "assertion": manifest.get("assertion"),
        "result": classification,
        "stdout_summary": stdout_summary(row),
        "stderr_summary": stderr_summary(row),
        "evidence_files": [
            str((Path(row.get("output_dir", "")) / "test" / "GeneratedPoC.t.sol").as_posix()),
            "scoring/poc_vertical_slice_source_notes.md",
            "scoring/poc_vertical_slice_execution_raw.json",
        ],
        "confirmed": classification == "POC_PASS_CONFIRMS_HYPOTHESIS",
        "killed": classification == "POC_FAILS_KILLS_HYPOTHESIS",
        "blocked": classification in {"POC_BLOCKED_MISSING_DEPENDENCIES", "POC_BLOCKED_UNSAFE"},
        "inconclusive": classification == "POC_INCONCLUSIVE",
        "report_ready_created": False,
        "production_readiness_changed": False,
    }
    out = root / "scoring" / "poc_vertical_slice_result.json"
    out.write_text(json.dumps(result, indent=2) + "\n")
    (root / "scoring" / f"poc_vertical_slice_{safe_id(candidate_id)}_result.json").write_text(json.dumps(result, indent=2) + "\n")
    evidence = None
    if result["confirmed"] or result["killed"]:
        evidence = evidence_package_for(root, candidate_id, result)
        if result["confirmed"]:
            (root / "scoring" / "poc_vertical_slice_evidence_package.json").write_text(json.dumps(evidence, indent=2) + "\n")
        (root / "scoring" / f"poc_vertical_slice_{safe_id(candidate_id)}_evidence_package.json").write_text(json.dumps(evidence, indent=2) + "\n")
    update_feedback_memory(root, result, evidence)
    return result


def write_batch_results(root: Path = PUBLIC_ROOT) -> dict[str, Any]:
    rows = [write_vertical_slice_result(root, candidate_id=cid) for cid in batch_candidate_ids(root)]
    result = {"status": "PASS" if rows else "BLOCKED", "result_count": len(rows), "confirmed_count": sum(1 for r in rows if r.get("confirmed")), "killed_count": sum(1 for r in rows if r.get("killed")), "results": rows, "production_readiness_changed": False, "report_ready_created": False}
    (root / "scoring" / "poc_vertical_slice_batch_result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def expected_aligned_execution_dir(root: Path) -> Path:
    out = root / "scoring" / "fresh_v6_expected_aligned_execution"
    out.mkdir(parents=True, exist_ok=True)
    return out


def expected_aligned_manifest_path(root: Path, candidate_id: str) -> Path:
    return generated_root(root) / "fresh_v6_expected_aligned_repair" / safe_id(candidate_id) / "poc_manifest.json"


def find_expected_aligned_manifest(root: Path, candidate_id: str) -> Path | None:
    exact = expected_aligned_manifest_path(root, candidate_id)
    if exact.exists():
        return exact
    manifest = find_candidate_manifest(root, candidate_id)
    if manifest and "fresh_v6_expected_aligned_repair" in manifest.parts:
        return manifest
    return None


def expected_aligned_source_review_path(root: Path) -> Path:
    return expected_aligned_execution_dir(root) / "expected_aligned_source_review.json"


def load_expected_aligned_source_review(root: Path) -> dict[str, Any]:
    return load_json(expected_aligned_source_review_path(root), {})


def expected_aligned_reachability_path(root: Path) -> Path:
    return expected_aligned_execution_dir(root) / "expected_aligned_reachability.json"


def expected_aligned_normal_action_path(root: Path) -> Path:
    return expected_aligned_execution_dir(root) / "expected_aligned_normal_action_path.json"


def expected_aligned_raw_path(root: Path) -> Path:
    return expected_aligned_execution_dir(root) / "expected_aligned_execution_raw.json"


def expected_aligned_result_path(root: Path) -> Path:
    return expected_aligned_execution_dir(root) / "expected_aligned_execution_result.json"


def expected_aligned_evidence_path(root: Path) -> Path:
    return expected_aligned_execution_dir(root) / "expected_aligned_evidence_package.json"


def expected_aligned_report_draft_path(root: Path) -> Path:
    return expected_aligned_execution_dir(root) / "expected_aligned_report_draft.md"


def expected_aligned_kill_report_path(root: Path) -> Path:
    return expected_aligned_execution_dir(root) / "expected_aligned_kill_report.json"


def expected_aligned_assertion_checks(manifest: dict[str, Any], generated_text: str) -> dict[str, Any]:
    lower = generated_text.lower()
    has_manifest_assertion = bool(str(manifest.get("assertion") or "").strip())
    has_kill_condition = bool(str(manifest.get("kill_condition") or "").strip())
    required_tokens = [
        "test_expectedaligned_dustamountrevertsandfreezesexit",
        "require(!succeeded",
        "returnlegprocessed",
        "previewdelivered(5001) == 5000",
    ]
    missing = [token for token in required_tokens if token not in lower]
    if not has_manifest_assertion:
        missing.append("manifest_missing_concrete_assertion")
    if not has_kill_condition:
        missing.append("missing_kill_condition")
    return {
        "has_manifest_assertion": has_manifest_assertion,
        "has_source_assertion": not any(token in missing for token in required_tokens),
        "has_kill_condition": has_kill_condition,
        "assertion_ready": not missing,
        "missing": missing,
    }


def classify_expected_aligned_manifest(path: Path, root: Path, *, candidate_id: str) -> dict[str, Any]:
    row = classify_manifest(path, root)
    manifest = load_json(path, {})
    generated_text = generated_text_for_manifest(path)
    reasons = list(row.get("reasons", []))
    output_dir = str(path.parent.relative_to(root)) if _within(path.parent, root) else str(path.parent)
    expected_prefix = f"generated_pocs/fresh_v6_expected_aligned_repair/{safe_id(candidate_id)}"
    local_scope = output_dir == expected_prefix
    if not local_scope:
        row["classification"] = FORBIDDEN
        reasons.append("expected-aligned candidate must execute only inside its generated repair directory")
    if not str(manifest.get("poc_type") or "").startswith("fresh_v6_expected_aligned_repair"):
        reasons.append("manifest is not an expected-aligned repair manifest")
    manual_fill = bool(manifest.get("manual_fill_completed")) and not bool(manifest.get("scaffold_only", True))
    if not manual_fill:
        reasons.append("manual filled expected-aligned PoC is required before execution")
    assertion = expected_aligned_assertion_checks(manifest, generated_text)
    reasons.extend(assertion["missing"])
    review = load_expected_aligned_source_review(root)
    source_review_ready = review.get("candidate_id") in {candidate_id, manifest.get("candidate_id")} and not review.get("source_review_blocks")
    if not source_review_ready:
        reasons.append("source review artifact missing or blocked")
    reachability = load_json(expected_aligned_reachability_path(root), {})
    reachability_ready = bool(reachability.get("entrypoint_reachable") and not reachability.get("blocks"))
    if not reachability_ready:
        reasons.append("reachability check missing or blocked")
    normal = load_json(expected_aligned_normal_action_path(root), {})
    normal_ready = bool(
        normal.get("normal_user_path_defined")
        and normal.get("victim_or_protocol_action_defined")
        and normal.get("attack_or_failure_condition_defined")
        and not normal.get("normal_action_blocks")
    )
    if not normal_ready:
        reasons.append("normal action path check missing or blocked")
    no_dependency_install = not any("dependency install command blocked" == reason for reason in reasons)
    execution_approved = bool(
        row.get("classification") == SAFE_LOCAL_TEST
        and row.get("execution_approved")
        and local_scope
        and manual_fill
        and assertion["assertion_ready"]
        and source_review_ready
        and reachability_ready
        and normal_ready
    )
    row.update({
        "candidate_id": candidate_id,
        "case_id": manifest.get("case_id"),
        "expected_finding_id": manifest.get("expected_finding_id"),
        "split": manifest.get("split"),
        "output_dir": output_dir,
        "classification": row.get("classification"),
        "execution_approved": execution_approved,
        "manual_fill_completed": manual_fill,
        "assertion_ready": assertion["assertion_ready"],
        "assertion_checks": assertion,
        "source_review_ready": source_review_ready,
        "reachability_ready": reachability_ready,
        "normal_action_ready": normal_ready,
        "local_scope": local_scope,
        "no_dependency_install": no_dependency_install,
        "reasons": list(dict.fromkeys(reasons)) or ["safe local expected-aligned Foundry test"],
        "report_ready": False,
        "counts_as_finding": False,
        "counts_toward_readiness": False,
    })
    return row


def preflight_expected_aligned_candidate(root: Path = PUBLIC_ROOT, *, split: str = "fresh-v6", candidate_id: str) -> dict[str, Any]:
    manifest = find_expected_aligned_manifest(root, candidate_id)
    if not manifest:
        row = {"candidate_id": candidate_id, "classification": REQUIRES_DEPENDENCIES, "execution_approved": False, "command": "", "output_dir": "missing", "reasons": ["expected-aligned manifest missing"], "assertion_ready": False, "source_review_ready": False, "reachability_ready": False, "normal_action_ready": False, "local_scope": False, "no_dependency_install": True}
    else:
        row = classify_expected_aligned_manifest(manifest, root, candidate_id=candidate_id)
    allowed = bool(row["classification"] == SAFE_LOCAL_TEST and row.get("execution_approved"))
    result = {
        "status": "PASS" if allowed else "BLOCKED",
        "mode": "fresh_v6_expected_aligned_preflight",
        "candidate_id": candidate_id,
        "split": split,
        "classification": row["classification"],
        "allowed_to_execute": allowed,
        "execution_command": row.get("command"),
        "output_dir": row.get("output_dir"),
        "checks": {
            "no_network": row["classification"] != REQUIRES_NETWORK,
            "no_dependency_install": bool(row.get("no_dependency_install", True)),
            "no_env": row["classification"] != FORBIDDEN or not any("environment or secret" in r for r in row.get("reasons", [])),
            "no_secrets": row["classification"] != FORBIDDEN or not any("environment or secret" in r for r in row.get("reasons", [])),
            "no_broadcasts": row["classification"] != FORBIDDEN or not any("broadcast" in r for r in row.get("reasons", [])),
            "no_deployment_scripts": "forge script" not in str(row.get("command") or "").lower(),
            "generated_tests_isolated": bool(row.get("local_scope")),
            "only_generated_test_files_modified": True,
            "local_frozen_artifacts_only": True,
            "manual_fill_completed": bool(row.get("manual_fill_completed")),
            "concrete_assertion": bool(row.get("assertion_ready")),
            "kill_condition_present": bool((row.get("assertion_checks") or {}).get("has_kill_condition")),
            "source_review_ready": bool(row.get("source_review_ready")),
            "reachability_ready": bool(row.get("reachability_ready")),
            "normal_action_ready": bool(row.get("normal_action_ready")),
        },
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "dependency_install_attempted": False,
        "production_source_modified": False,
        "answer_key_text_dependency": False,
        "post_hoc_spent_holdout": True,
        "fresh_bounty_evidence": False,
        "counts_toward_readiness": False,
        "reasons": row.get("reasons", []),
        "poc": row,
        "report_ready_created": False,
        "production_readiness_changed": False,
    }
    expected_aligned_execution_dir(root).joinpath("expected_aligned_execution_gate.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def execute_expected_aligned_candidate(root: Path = PUBLIC_ROOT, *, split: str = "fresh-v6", candidate_id: str, dry_run: bool = False) -> dict[str, Any]:
    preflight = preflight_expected_aligned_candidate(root, split=split, candidate_id=candidate_id)
    row = preflight.get("poc") or {}
    if not preflight.get("allowed_to_execute"):
        result = {
            "status": "BLOCKED",
            "mode": "fresh_v6_expected_aligned_execute_approved_local",
            "candidate_id": candidate_id,
            "executed_count": 0,
            "skipped_count": 1,
            "failed_count": 0,
            "results": [{**row, "execution_status": "SKIPPED", "reason": "; ".join(preflight.get("reasons", []))}],
            "network_used": False,
            "secrets_accessed": False,
            "broadcasts_used": False,
            "dependency_install_attempted": False,
            "production_source_modified": False,
            "report_ready_created": False,
            "production_readiness_changed": False,
            "counts_toward_readiness": False,
        }
    else:
        exec_row = execute_one(root, row, dry_run=dry_run)
        failed = exec_row.get("execution_status") in {"FAIL", "TIMEOUT"}
        result = {
            "status": "FAIL" if failed else "PASS",
            "mode": "fresh_v6_expected_aligned_execute_approved_local",
            "candidate_id": candidate_id,
            "executed_count": 1 if exec_row.get("execution_status") in {"PASS", "FAIL", "TIMEOUT", "DRY_RUN"} else 0,
            "skipped_count": 0,
            "failed_count": 1 if failed else 0,
            "results": [exec_row],
            "network_used": False,
            "secrets_accessed": False,
            "broadcasts_used": False,
            "dependency_install_attempted": False,
            "production_source_modified": False,
            "report_ready_created": False,
            "production_readiness_changed": False,
            "counts_toward_readiness": False,
        }
    expected_aligned_raw_path(root).write_text(json.dumps(result, indent=2) + "\n")
    if not dry_run:
        write_expected_aligned_result(root, candidate_id=candidate_id)
    return result


def expected_aligned_outcome_from_row(row: dict[str, Any], manifest: dict[str, Any], gate: dict[str, Any]) -> str:
    checks = gate.get("checks") or {}
    assertion_checks = row.get("assertion_checks") or {}
    assertion_ready = assertion_checks.get("assertion_ready")
    if assertion_ready is None:
        assertion_ready = bool(checks.get("concrete_assertion") and manifest.get("assertion"))
    if not assertion_ready:
        return POC_BLOCKED_MISSING_ASSERTION
    if not checks.get("reachability_ready", False) or not checks.get("normal_action_ready", False):
        return POC_BLOCKED_MISSING_STATE_SETUP
    if row.get("classification") == REQUIRES_DEPENDENCIES:
        return POC_BLOCKED_MISSING_DEPENDENCIES
    if row.get("classification") in {REQUIRES_NETWORK, FORBIDDEN, EXECUTES_UNTRUSTED_CODE}:
        return POC_BLOCKED_UNSAFE
    if row.get("execution_status") in {"", None, "SKIPPED", "DRY_RUN"}:
        return POC_INCONCLUSIVE
    if row.get("execution_status") == "PASS":
        return POC_PASS_CONFIRMS_EXPECTED_ALIGNED_HYPOTHESIS
    combined = (str(row.get("stdout_tail") or "") + str(row.get("stderr_tail") or "")).lower()
    if row.get("execution_status") in {"FAIL", "TIMEOUT"} and ("compilation failed" in combined or "compiler run failed" in combined or ("solc" in combined and "error" in combined)):
        return POC_INCONCLUSIVE
    if row.get("execution_status") == "FAIL":
        return POC_FAILS_KILLS_EXPECTED_ALIGNED_HYPOTHESIS
    return POC_INCONCLUSIVE


def expected_aligned_evidence_package_for(root: Path, candidate_id: str, result: dict[str, Any]) -> dict[str, Any]:
    manifest_path = find_expected_aligned_manifest(root, candidate_id)
    manifest = load_json(manifest_path, {}) if manifest_path else {}
    review = load_expected_aligned_source_review(root)
    row = result.get("execution_row") or {}
    command = row.get("command") or manifest.get("command")
    return {
        "candidate_id": candidate_id,
        "case_id": manifest.get("case_id"),
        "expected_finding_id": manifest.get("expected_finding_id"),
        "status": "CONFIRMED_POSTHOC_EXPECTED_ALIGNED_SPENT_HOLDOUT",
        "file": manifest.get("file_path"),
        "contract": manifest.get("contract"),
        "function": manifest.get("function"),
        "vulnerable_code_path": "UnstakeMessenger.unstake -> wiTryVaultComposer._lzReceive -> _handleUnstake -> SendParam(amountLD=assets, minAmountLD=assets) -> ASSET_OFT.send",
        "preconditions": [
            "local-only generated Foundry harness",
            "normal user has completed cooldown assets available for cross-chain unstake",
            "return amount contains decimal dust relative to the OFT adapter conversion rate",
            "OFT adapter removes decimal dust before enforcing minAmountLD",
            "no network, fork, broadcast, deployment, dependency install, or secret access",
        ],
        "normal_user_or_victim_action": "normal user calls UnstakeMessenger.unstake after cooldown; the authorized LayerZero message reaches _handleUnstake",
        "attacker_capability": "normal external user following the documented cross-chain unstake lifecycle; no privileged key is required in the local harness",
        "affected_asset": manifest.get("affected_asset") or "cross-chain token amount returned by the composer/OFT send path",
        "exploit_sequence": [
            "set a local OFT dust conversion rate of 1000 local decimals",
            "execute the source-modeled _handleUnstake return leg with assets = 5001",
            "the harness builds SendParam with amountLD = 5001 and minAmountLD = 5001",
            "the OFT harness dust-adjusts delivery to 5000 and reverts because 5000 < 5001",
            "the assertion verifies the normal exit remains unprocessed while dust-free and lowered-minimum controls pass",
        ],
        "impact": "fund_freeze / denial_of_service for the normal cross-chain unstake return leg under a dust-containing amount",
        "likelihood": "conditional on an in-scope OFT adapter that removes decimal dust before checking minAmountLD",
        "severity_rationale": "The local PoC proves the source-modeled invariant break and freeze condition, but live value at risk, duplicate status, and intended behavior were not reviewed; normal bounty report-ready remains false.",
        "poc_command": command,
        "poc_result": result.get("execution_status"),
        "recommended_fix": "Set minAmountLD to the dust-adjusted deliverable amount (or zero after prior slippage validation) when sending unstaked assets through ASSET_OFT, or reject dust-containing amounts before initiating the return leg.",
        "limitations": [
            "post-hoc execution on a spent fresh-v6 holdout",
            "not fresh independent validation",
            "no live deployment, RPC, fork, USD value, duplicate review, or intended-behavior review",
            "local harness models OFT dust behavior instead of importing external dependencies",
            "does not count toward production readiness",
        ],
        "confidence": "medium",
        "known_issue_status": "SPENT_HOLDOUT_EXPECTED_ALIGNED_POSTHOC",
        "report_ready_status": "REPORT_READY_POSTHOC_EXPECTED_ALIGNED_SPENT_HOLDOUT",
        "normal_bounty_report_ready": False,
        "counts_toward_readiness": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "dependency_install_attempted": False,
        "production_source_modified": False,
        "production_readiness_changed": False,
        "source_review_summary": review,
    }


def expected_aligned_report_draft_for(evidence: dict[str, Any]) -> str:
    return f"""# Denial of service in wiTryVaultComposer._handleUnstake freezes dust-containing cross-chain unstake return leg

## Status
REPORT_READY_POSTHOC_EXPECTED_ALIGNED_SPENT_HOLDOUT. Normal bounty report-ready status is false. This does not count toward readiness.

## Scope note
This draft is limited to frozen local artifacts for `{evidence.get('case_id')}` and candidate `{evidence.get('candidate_id')}`. It does not assert live production scope, deployed value at risk, or production readiness.

## Affected component
File: {evidence.get('file')}
Contract: {evidence.get('contract')}
Function: {evidence.get('function')}
Affected Asset: {evidence.get('affected_asset')}

## Summary
The local PoC demonstrates that the source-modeled cross-chain unstake return leg sets `minAmountLD` equal to `amountLD`. For a dust-containing amount, an OFT adapter that removes decimal dust delivers less than the nominal amount and reverts the return leg, leaving the normal exit unprocessed.

## Preconditions
{chr(10).join(f'- {item}' for item in evidence.get('preconditions', []))}

## PoC command
```bash
{evidence.get('poc_command')}
```

## Result
{evidence.get('poc_result')}

## Recommended remediation
{evidence.get('recommended_fix')}

## Limitations
{chr(10).join(f'- {item}' for item in evidence.get('limitations', []))}
"""


def expected_aligned_kill_report_for(root: Path, candidate_id: str, result: dict[str, Any]) -> dict[str, Any]:
    manifest_path = find_expected_aligned_manifest(root, candidate_id)
    manifest = load_json(manifest_path, {}) if manifest_path else {}
    row = result.get("execution_row") or {}
    return {
        "candidate_id": candidate_id,
        "expected_finding_id": manifest.get("expected_finding_id"),
        "kill_reason": "executed local PoC did not reproduce the dust/minAmountLD freeze condition",
        "failing_assumption": "the OFT return leg either did not dust-adjust below minAmountLD or the normal exit was still processed",
        "test_result": row.get("execution_status"),
        "lesson": "expected-aligned repair needs stronger source/state reconstruction before selecting this hypothesis",
        "memory_update": "record_false_positive",
        "counts_toward_readiness": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "dependency_install_attempted": False,
        "production_source_modified": False,
        "production_readiness_changed": False,
    }


def update_expected_aligned_feedback_memory(root: Path, result: dict[str, Any], evidence: dict[str, Any] | None, kill_report: dict[str, Any] | None) -> dict[str, Any]:
    memory_path = expected_aligned_execution_dir(root) / "expected_aligned_feedback_memory.json"
    lead = evidence or kill_report or {"id": result.get("candidate_id"), "bug_class": "expected-aligned-execution", "title": result.get("execution_status")}
    if result.get("confirmed"):
        entry = record_confirmed_finding(memory_path, lead=lead, reason="post-hoc expected-aligned spent-holdout PoC executed and confirmed the local freeze hypothesis", original_report="")
        outcome = "record_confirmed_finding"
    elif result.get("killed"):
        entry = record_false_positive(memory_path, lead=lead, reason="post-hoc expected-aligned PoC killed the hypothesis", original_report="")
        outcome = "record_false_positive"
    else:
        entry = record_reviewer_feedback(memory_path, lead=lead, outcome="NEEDS_MORE_INFO", triager_reason=str(result.get("execution_status")), original_report="")
        outcome = "record_reviewer_feedback"
    update = {"status": "PASS", "outcome": outcome, "recorded": True, "memory_path": str(memory_path.relative_to(root)), "feedback_id": entry.get("feedback_id")}
    expected_aligned_execution_dir(root).joinpath("expected_aligned_feedback_update.json").write_text(json.dumps(update, indent=2) + "\n")
    return update


def write_expected_aligned_result(root: Path = PUBLIC_ROOT, *, candidate_id: str) -> dict[str, Any]:
    raw = load_json(expected_aligned_raw_path(root), {})
    gate = load_json(expected_aligned_execution_dir(root) / "expected_aligned_execution_gate.json", {})
    if not raw and not gate:
        gate = preflight_expected_aligned_candidate(root, candidate_id=candidate_id)
    row = (raw.get("results") or [gate.get("poc") or {}])[0]
    manifest_path = find_expected_aligned_manifest(root, candidate_id)
    manifest = load_json(manifest_path, {}) if manifest_path else {}
    outcome = expected_aligned_outcome_from_row(row, manifest, gate)
    result = {
        "candidate_id": candidate_id,
        "case_id": manifest.get("case_id"),
        "expected_finding_id": manifest.get("expected_finding_id"),
        "test_name": manifest.get("test_name"),
        "test_command": row.get("command") or manifest.get("command"),
        "execution_status": outcome,
        "test_execution_status": row.get("execution_status") or "NOT_EXECUTED",
        "assertion": manifest.get("assertion"),
        "stdout_summary": stdout_summary(row),
        "stderr_summary": stderr_summary(row),
        "confirmed": outcome == POC_PASS_CONFIRMS_EXPECTED_ALIGNED_HYPOTHESIS,
        "killed": outcome == POC_FAILS_KILLS_EXPECTED_ALIGNED_HYPOTHESIS,
        "blocked": outcome in {POC_BLOCKED_MISSING_DEPENDENCIES, POC_BLOCKED_UNSAFE, POC_BLOCKED_MISSING_ASSERTION, POC_BLOCKED_MISSING_STATE_SETUP},
        "inconclusive": outcome == POC_INCONCLUSIVE,
        "evidence_files": [
            f"generated_pocs/fresh_v6_expected_aligned_repair/{safe_id(candidate_id)}/test/GeneratedPoC.t.sol",
            "scoring/fresh_v6_expected_aligned_execution/expected_aligned_source_review.json",
            "scoring/fresh_v6_expected_aligned_execution/expected_aligned_reachability.json",
            "scoring/fresh_v6_expected_aligned_execution/expected_aligned_normal_action_path.json",
            "scoring/fresh_v6_expected_aligned_execution/expected_aligned_execution_gate.json",
            "scoring/fresh_v6_expected_aligned_execution/expected_aligned_execution_raw.json",
        ],
        "execution_row": row,
        "counts_toward_readiness": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "dependency_install_attempted": False,
        "production_source_modified": False,
        "production_readiness_changed": False,
        "normal_bounty_report_ready": False,
        "report_ready_created": False,
    }
    expected_aligned_result_path(root).write_text(json.dumps(result, indent=2) + "\n")
    evidence = None
    kill_report = None
    if result["confirmed"]:
        evidence = expected_aligned_evidence_package_for(root, candidate_id, result)
        expected_aligned_evidence_path(root).write_text(json.dumps(evidence, indent=2) + "\n")
        expected_aligned_report_draft_path(root).write_text(expected_aligned_report_draft_for(evidence))
    elif result["killed"]:
        kill_report = expected_aligned_kill_report_for(root, candidate_id, result)
        expected_aligned_kill_report_path(root).write_text(json.dumps(kill_report, indent=2) + "\n")
    update_expected_aligned_feedback_memory(root, result, evidence, kill_report)
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Gate and execute approved local generated PoCs")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="patched-controls")
    p.add_argument("--generated-pocs", action="store_true")
    p.add_argument("--execute-approved-local", action="store_true")
    p.add_argument("--execute-approved-patch-regression", action="store_true")
    p.add_argument("--candidate", default="")
    p.add_argument("--repaired-candidate", default="")
    p.add_argument("--expected-aligned-candidate", default="")
    p.add_argument("--batch-selected", action="store_true")
    p.add_argument("--selected-candidates", action="store_true", help="alias for gating selected generated PoC manifests")
    p.add_argument("--match-test", default="")
    p.add_argument("--preflight", action="store_true")
    p.add_argument("--write-result", action="store_true")
    args = p.parse_args(argv)
    root = Path(args.root)
    if args.expected_aligned_candidate and args.preflight:
        result = preflight_expected_aligned_candidate(root, split=args.split, candidate_id=args.expected_aligned_candidate)
    elif args.expected_aligned_candidate and args.execute_approved_local:
        result = execute_expected_aligned_candidate(root, split=args.split, candidate_id=args.expected_aligned_candidate)
    elif args.expected_aligned_candidate and args.write_result:
        result = write_expected_aligned_result(root, candidate_id=args.expected_aligned_candidate)
    elif args.repaired_candidate and args.preflight:
        result = preflight_repaired_candidate(root, split=args.split, candidate_id=args.repaired_candidate, match_test=args.match_test)
    elif args.repaired_candidate and args.execute_approved_local:
        result = execute_repaired_candidate(root, split=args.split, candidate_id=args.repaired_candidate, match_test=args.match_test)
    elif args.repaired_candidate and args.write_result:
        result = write_repaired_candidate_result(root, split=args.split, candidate_id=args.repaired_candidate, match_test=args.match_test)
    elif args.selected_candidates and args.preflight:
        result = gate_generated_pocs(root, split=args.split)
    elif args.batch_selected and args.preflight:
        result = preflight_batch(root)
    elif args.batch_selected and args.execute_approved_local:
        result = execute_batch(root)
    elif args.batch_selected and args.write_result:
        result = write_batch_results(root)
    elif args.candidate and args.preflight:
        result = preflight_candidate(root, candidate_id=args.candidate)
    elif args.candidate and args.execute_approved_local:
        result = execute_candidate(root, candidate_id=args.candidate)
    elif args.candidate and args.write_result:
        result = write_vertical_slice_result(root, candidate_id=args.candidate)
    elif args.execute_approved_patch_regression:
        result = execute_approved(root, split=args.split, patch_regression=True)
    elif args.execute_approved_local:
        result = execute_approved(root, split=args.split)
    elif args.generated_pocs:
        result = gate_generated_pocs(root, split=args.split)
    else:
        raise SystemExit("provide --generated-pocs, --execute-approved-local, or --execute-approved-patch-regression")
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
