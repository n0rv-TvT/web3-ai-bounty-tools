#!/usr/bin/env python3
"""JSON schema and semantic validation for Web3 audit-agent artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas"
SCHEMA_FILES = {
    "finding": "finding.schema.json",
    "lead": "lead.schema.json",
    "feedback_memory": "feedback_memory.schema.json",
    "lifecycle_model": "lifecycle_model.schema.json",
    "mev_lead": "mev_lead.schema.json",
    "cross_chain_lead": "cross_chain_lead.schema.json",
    "recon_result": "recon_result.schema.json",
    "implementation_history": "implementation_history.schema.json",
    "report_lint_result": "report_lint_result.schema.json",
    "real_world_corpus_manifest": "real_world_corpus_manifest.schema.json",
    "expected_finding": "expected_finding.schema.json",
    "generated_audit_finding": "generated_audit_finding.schema.json",
    "ood_score": "ood_score.schema.json",
    "public_historical_manifest": "public_historical_manifest.schema.json",
}


def load_schema(schema_name: str) -> dict[str, Any]:
    filename = SCHEMA_FILES.get(schema_name)
    if not filename:
        raise SystemExit(f"Unknown schema: {schema_name}")
    path = SCHEMA_DIR / filename
    if not path.exists():
        raise SystemExit(f"Missing schema file: {path}")
    return json.loads(path.read_text(errors="replace"))


def jsonschema_errors(schema: dict[str, Any], payload: dict[str, Any]) -> list[str]:
    try:
        import jsonschema  # type: ignore
    except ImportError as exc:
        raise SystemExit("jsonschema is required for schema validation") from exc
    validator = jsonschema.Draft202012Validator(schema)
    return [f"/{'/'.join(str(x) for x in err.path)}: {err.message}" for err in sorted(validator.iter_errors(payload), key=lambda e: list(e.path))]


def semantic_errors(schema_name: str, payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not payload:
        errors.append("empty JSON object is invalid")
    if schema_name in {"finding", "lead"}:
        state = payload.get("state")
        if state and state not in load_schema("finding")["$defs"]["state"]["enum"]:
            errors.append(f"unknown state: {state}")
        severity = payload.get("severity")
        if severity and severity not in load_schema("finding")["$defs"]["severity"]["enum"]:
            errors.append(f"invalid severity: {severity}")
        if payload.get("impact", {}).get("type") in {"stolen-funds", "bad-debt", "frozen-funds"}:
            financial = payload.get("financial_impact") or {}
            for field in ["currency", "amount", "assumption_source", "calculation_method"]:
                if not financial.get(field):
                    errors.append(f"financial impact missing {field}")
    if schema_name == "mev_lead" and not payload.get("ordered_transaction_sequence"):
        errors.append("MEV lead missing ordered_transaction_sequence")
    if schema_name == "cross_chain_lead" and not payload.get("message_path"):
        errors.append("cross-chain lead missing message_path")
    return errors


def validate_payload(schema_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    schema = load_schema(schema_name)
    errors = jsonschema_errors(schema, payload) + semantic_errors(schema_name, payload)
    return {"schema": schema_name, "valid": not errors, "errors": errors}


def validate_file(schema_name: str, path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"JSON file does not exist: {path}")
    payload = json.loads(path.read_text(errors="replace"))
    if not isinstance(payload, dict):
        return {"schema": schema_name, "valid": False, "errors": ["root must be object"]}
    return validate_payload(schema_name, payload)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Validate Web3 audit-agent JSON artifacts")
    p.add_argument("schema")
    p.add_argument("json_file")
    args = p.parse_args(argv)
    result = validate_file(args.schema, Path(args.json_file))
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
