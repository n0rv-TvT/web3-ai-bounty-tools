#!/usr/bin/env python3
"""Hash and freeze benchmark artifacts before answer-key scoring."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_payload(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def freeze_report(report: dict[str, Any]) -> dict[str, Any]:
    frozen = copy.deepcopy(report)
    frozen.pop("report_hash", None)
    frozen.setdefault("answer_key_loaded", False)
    frozen["frozen_at"] = datetime.now(timezone.utc).isoformat()
    frozen["report_hash"] = sha256_payload(frozen)
    return frozen


def verify_frozen_report(report: dict[str, Any]) -> bool:
    if not report.get("frozen_at") or not report.get("report_hash"):
        return False
    expected = report.get("report_hash")
    tmp = copy.deepcopy(report)
    tmp.pop("report_hash", None)
    return sha256_payload(tmp) == expected


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Hash or freeze JSON artifacts")
    p.add_argument("json_file")
    p.add_argument("--freeze", action="store_true")
    args = p.parse_args(argv)
    path = Path(args.json_file)
    if args.freeze:
        payload = json.loads(path.read_text(errors="replace"))
        frozen = freeze_report(payload)
        path.write_text(json.dumps(frozen, indent=2) + "\n")
        print(json.dumps({"path": str(path), "report_hash": frozen["report_hash"], "frozen_at": frozen["frozen_at"]}, indent=2))
    else:
        print(json.dumps({"path": str(path), "sha256": sha256_file(path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
