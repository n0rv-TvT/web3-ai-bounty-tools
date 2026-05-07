#!/usr/bin/env python3
"""Generate human adjudication packets for public benchmark cases."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from public_finding_matcher import public_match_case
from public_report_quality_scorer import public_score_finding


PUBLIC_ROOT = Path(__file__).resolve().parents[1] / "benchmarks" / "public-historical-corpus"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace"))


def packet_for_case(root: Path, case: dict[str, Any]) -> dict[str, Any]:
    report_path = root / "generated_reports" / f"{case['case_id']}.json"
    report = load_json(report_path) if report_path.exists() else {"findings": []}
    expected = load_json(root / case["answer_key_path"]) if (root / case["answer_key_path"]).exists() else {"case_id": case["case_id"]}
    match = public_match_case(expected, report.get("findings", []))
    finding = report.get("findings", [{}])[0] if report.get("findings") else {}
    quality = public_score_finding(finding) if finding else {"score": 0, "checks": {}}
    out = root / "adjudication" / f"{case['case_id']}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(f"""# Public Benchmark Adjudication Packet: {case['case_id']}

## Source Metadata
- Source name: {case.get('source_name')}
- Source URL: {case.get('source_url')}
- Commit/version: {case.get('commit_hash')}
- License note: {case.get('license_note')}

## Generated Finding
```json
{json.dumps(finding, indent=2)}
```

## Expected Finding (for adjudication only)
```json
{json.dumps(expected, indent=2)}
```

## Match Result
```json
{json.dumps(match, indent=2)}
```

## Report Quality
```json
{json.dumps(quality, indent=2)}
```

## Human Review Questions
- Did the agent identify the same root cause?
- Did it identify the correct file/function?
- Did it explain a realistic exploit path?
- Was severity reasonable?
- Did it overstate impact?
- Did it miss important preconditions?
- Would this be acceptable in a real audit report?
""")
    return {"case_id": case["case_id"], "packet": out.relative_to(root).as_posix(), "needs_human_review": True, "reason": "public historical scoring requires human adjudication"}


def generate_packets(root: Path = PUBLIC_ROOT) -> dict[str, Any]:
    manifest_path = root / "corpus_manifest.json"
    if not manifest_path.exists():
        return {"status": "BLOCKED", "reason": "missing public corpus manifest", "packet_count": 0, "packets": []}
    manifest = load_json(manifest_path)
    cases = manifest.get("cases", [])
    packets = [packet_for_case(root, case) for case in cases]
    return {"status": "PASS" if cases else "BLOCKED", "reason": "no public cases imported" if not cases else "packets generated", "packet_count": len(packets), "packets": packets}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Generate public benchmark adjudication packets")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    args = p.parse_args(argv)
    result = generate_packets(Path(args.root))
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
