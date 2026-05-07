#!/usr/bin/env python3
"""Local benchmark fixture loader and metric calculator."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any


BENCHMARK_ROOT = Path(__file__).resolve().parents[1] / "benchmarks"
SOLIDITY_FIXTURE_ROOT = BENCHMARK_ROOT / "solidity-fixtures"
REQUIRED_METADATA = ["fixture_name", "bug_class", "expected_finding", "expected_severity", "required_evidence", "false_positive_trap", "passing_criteria"]
REQUIRED_SOLIDITY_FINDING = ["fixture_name", "bug_class", "expected_severity", "source_file", "test_file", "expected_test", "affected_contract", "affected_function", "expected_impact", "required_assertions", "poc_command"]
FORBIDDEN_SOLIDITY_BENCHMARK_PATTERNS = ["vm.env", "createFork", "fork", "--broadcast", "cast send", "ffi", "rpc_url", ".env", "private_key", "mnemonic"]


def load_fixture(path: Path) -> dict[str, Any]:
    meta = path / "metadata.json"
    if not meta.exists():
        raise SystemExit(f"Benchmark fixture missing metadata: {path}")
    data = json.loads(meta.read_text(errors="replace"))
    missing = [field for field in REQUIRED_METADATA if not data.get(field)]
    if missing:
        raise SystemExit(f"Benchmark fixture {path.name} missing metadata fields: {', '.join(missing)}")
    return data


def load_benchmarks(root: Path = BENCHMARK_ROOT) -> list[dict[str, Any]]:
    if not root.exists():
        return []
    return [load_fixture(path) for path in sorted(root.iterdir()) if path.is_dir() and (path / "metadata.json").exists()]


def load_solidity_expected_finding(path: Path, *, project_root: Path = SOLIDITY_FIXTURE_ROOT) -> dict[str, Any]:
    data = json.loads(path.read_text(errors="replace"))
    missing = [field for field in REQUIRED_SOLIDITY_FINDING if not data.get(field)]
    if missing:
        raise SystemExit(f"Solidity expected finding {path.name} missing fields: {', '.join(missing)}")
    for field in ["source_file", "test_file"]:
        rel = Path(str(data[field]))
        if rel.is_absolute() or ".." in rel.parts:
            raise SystemExit(f"Solidity expected finding {path.name} has unsafe {field}: {data[field]}")
        if not (project_root / rel).exists():
            raise SystemExit(f"Solidity expected finding {path.name} references missing {field}: {data[field]}")
    source_text = (project_root / str(data["source_file"])).read_text(errors="replace")
    test_text = (project_root / str(data["test_file"])).read_text(errors="replace")
    combined = f"{source_text}\n{test_text}".lower()
    forbidden = [token for token in FORBIDDEN_SOLIDITY_BENCHMARK_PATTERNS if token in combined]
    if forbidden:
        raise SystemExit(f"Solidity expected finding {path.name} contains forbidden local-only pattern(s): {', '.join(forbidden)}")
    if str(data["affected_contract"]) not in source_text:
        raise SystemExit(f"Solidity expected finding {path.name} affected_contract not found in source")
    if str(data["affected_function"]) not in source_text:
        raise SystemExit(f"Solidity expected finding {path.name} affected_function not found in source")
    if str(data["expected_test"]) not in test_text:
        raise SystemExit(f"Solidity expected finding {path.name} expected_test not found in test file")
    if "assert" not in test_text:
        raise SystemExit(f"Solidity expected finding {path.name} test file has no assertions")
    if str(data["expected_test"]) not in str(data["poc_command"]):
        raise SystemExit(f"Solidity expected finding {path.name} poc_command must target expected_test")
    if not isinstance(data.get("required_assertions"), list) or not data["required_assertions"]:
        raise SystemExit(f"Solidity expected finding {path.name} requires non-empty required_assertions")
    return data


def load_solidity_expected_findings(project_root: Path = SOLIDITY_FIXTURE_ROOT) -> list[dict[str, Any]]:
    expected_dir = project_root / "expected_findings"
    if not expected_dir.exists():
        return []
    return [load_solidity_expected_finding(path, project_root=project_root) for path in sorted(expected_dir.glob("*.json"))]


def validate_solidity_fixture_project(project_root: Path = SOLIDITY_FIXTURE_ROOT) -> dict[str, Any]:
    blocks: list[str] = []
    for rel in ["foundry.toml", "src", "test", "expected_findings", "README.md"]:
        if not (project_root / rel).exists():
            blocks.append(f"missing {rel}")
    findings: list[dict[str, Any]] = []
    if not blocks:
        try:
            findings = load_solidity_expected_findings(project_root)
        except SystemExit as exc:
            blocks.append(str(exc))
    if not findings:
        blocks.append("no Solidity expected finding metadata loaded")
    return {"status": "PASS" if not blocks else "FAIL", "fixture_count": len(findings), "blocks": blocks, "fixtures": findings}


def run_foundry_tests(project_root: Path = SOLIDITY_FIXTURE_ROOT, *, timeout: int = 120) -> dict[str, Any]:
    command = ["forge", "test", "--root", str(project_root)]
    completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    return {
        "command": " ".join(command),
        "returncode": completed.returncode,
        "status": "PASS" if completed.returncode == 0 else "FAIL",
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-4000:],
    }


def run_solidity_benchmarks(project_root: Path = SOLIDITY_FIXTURE_ROOT, *, run_foundry: bool = False) -> dict[str, Any]:
    validation = validate_solidity_fixture_project(project_root)
    foundry = run_foundry_tests(project_root) if run_foundry and validation["status"] == "PASS" else None
    status = validation["status"]
    if foundry and foundry["status"] != "PASS":
        status = "FAIL"
    return {"status": status, "project_root": str(project_root), "validation": validation, "foundry": foundry}


def run_blind_delegate(project_root: Path, *, with_tests: bool = False, safe_controls: bool = False, do_score: bool = False, mutate_names: bool = False, mutate_comments: bool = False, mutate_layout: bool = False) -> dict[str, Any]:
    from blind_benchmark_runner import run_blind_benchmark

    return run_blind_benchmark(project_root, with_tests=with_tests, safe_controls=safe_controls, do_score=do_score, mutate_names_flag=mutate_names, mutate_comments_flag=mutate_comments, mutate_layout_flag=mutate_layout)


def compute_metrics(fixtures: list[dict[str, Any]], results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    total = len(fixtures)
    detected = correct_sev = report_ready = poc = false_pos = missed_critical = pipeline_block_correct = 0
    for fx in fixtures:
        name = fx["fixture_name"]
        res = results.get(name, {})
        if res.get("detected"):
            detected += 1
        if res.get("reported_false_positive"):
            false_pos += 1
        if res.get("severity") == fx["expected_severity"]:
            correct_sev += 1
        if res.get("report_ready") == fx.get("should_be_report_ready", True):
            report_ready += 1
        if res.get("poc_or_reproduction"):
            poc += 1
        if fx["expected_severity"] == "Critical" and not res.get("detected"):
            missed_critical += 1
        if res.get("pipeline_status") in {"REPORT_READY", "BLOCKED", "HYPOTHESIS_ONLY", "NEEDS_CONTEXT"}:
            pipeline_block_correct += 1
    denom = total or 1
    return {
        "fixture_count": total,
        "detection_rate": detected / denom,
        "false_positive_rate": false_pos / denom,
        "correct_severity_rate": correct_sev / denom,
        "report_ready_correctness_rate": report_ready / denom,
        "poc_reproduction_rate": poc / denom,
        "missed_critical_count": missed_critical,
        "pipeline_block_correctness_rate": pipeline_block_correct / denom,
    }


def self_test() -> dict[str, Any]:
    fixtures = load_benchmarks()
    results = {fx["fixture_name"]: {"detected": True, "severity": fx["expected_severity"], "report_ready": fx.get("should_be_report_ready", True), "poc_or_reproduction": True, "pipeline_status": "REPORT_READY"} for fx in fixtures}
    metrics = compute_metrics(fixtures, results)
    solidity = validate_solidity_fixture_project()
    return {"status": "PASS" if fixtures and metrics["detection_rate"] == 1 and solidity["status"] == "PASS" else "FAIL", "metrics": metrics, "solidity_fixture_count": solidity["fixture_count"]}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Run local benchmark fixture metrics")
    p.add_argument("--root", default=str(BENCHMARK_ROOT))
    p.add_argument("--results-json")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--solidity", action="store_true", help="validate executable Solidity benchmark fixtures")
    p.add_argument("--run-foundry", action="store_true", help="run forge test for Solidity benchmark fixtures")
    p.add_argument("--blind", action="store_true", help="run blind source-to-finding benchmark")
    p.add_argument("--with-tests", action="store_true", help="allow blind mode to inspect/run tests after source analysis")
    p.add_argument("--safe-controls", action="store_true", help="score safe controls as negative examples")
    p.add_argument("--score", action="store_true", help="load answer key after detection and score")
    p.add_argument("--mutate-names", action="store_true")
    p.add_argument("--mutate-comments", action="store_true")
    p.add_argument("--mutate-layout", action="store_true")
    args = p.parse_args(argv)
    if args.self_test:
        result = self_test()
    elif args.solidity:
        root = Path(args.root) if args.root != str(BENCHMARK_ROOT) else SOLIDITY_FIXTURE_ROOT
        if args.blind:
            result = run_blind_delegate(root, with_tests=args.with_tests, safe_controls=args.safe_controls, do_score=args.score, mutate_names=args.mutate_names, mutate_comments=args.mutate_comments, mutate_layout=args.mutate_layout)
        else:
            result = run_solidity_benchmarks(root, run_foundry=args.run_foundry)
    else:
        fixtures = load_benchmarks(Path(args.root))
        results = json.loads(Path(args.results_json).read_text(errors="replace")) if args.results_json else {}
        result = {"fixtures": fixtures, "metrics": compute_metrics(fixtures, results)}
    print(json.dumps(result, indent=2))
    return 0 if result.get("status", "PASS") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
