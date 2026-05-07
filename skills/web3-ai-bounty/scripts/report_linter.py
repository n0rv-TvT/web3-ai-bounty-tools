#!/usr/bin/env python3
"""Impact-first Immunefi-style report linter.

The linter is intentionally blocking-only: it reports exact blockers with line
numbers where applicable and never suggests rewrites. Zero blocks means the
report can proceed to submission review; any block stops submission.
"""

from __future__ import annotations

import argparse
import json
import re
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from economic_modeler import economic_proof_schema_path, validate_economic_proof
from report_ready_closure_utils import closure_path, load_json, safety_metadata
from report_draft_builder import REQUIRED_REPORT_SECTIONS


SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
SPECULATIVE_PHRASES = [
    "could potentially",
    "it is possible that",
    "we believe",
    "this might",
    "appears to",
    "seems to",
    "could",
    "might",
    "may",
    "possibly",
    "potentially",
    "likely",
    "probably",
]


def decimal_value(value: Any, field: str) -> Decimal:
    try:
        d = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise SystemExit(f"Invalid decimal for {field}: {value}") from exc
    if not d.is_finite():
        raise SystemExit(f"Invalid finite decimal for {field}: {value}")
    return d


def load_report(
    report_input: Path | dict[str, Any] | str,
) -> tuple[str, dict[str, Any] | None]:
    """Load markdown report text or structured report dict."""

    if isinstance(report_input, Path):
        if not report_input.exists():
            raise SystemExit(f"Report does not exist: {report_input}")
        return report_input.read_text(errors="replace"), None
    if isinstance(report_input, dict):
        lines: list[str] = []
        for key, value in report_input.items():
            lines.append(f"## {key}")
            lines.append(str(value))
            lines.append("")
        return "\n".join(lines), report_input
    return str(report_input), None


def load_lead_db(path: Path) -> dict[str, Any]:
    """Load Lead DB JSON."""

    if not path.exists():
        raise SystemExit(f"Lead DB does not exist: {path}")
    data = json.loads(path.read_text(errors="replace"))
    if not isinstance(data, dict):
        raise SystemExit(f"Lead DB root must be an object: {path}")
    return data


def load_lead(
    db: dict[str, Any],
    lead_id: str,
) -> dict[str, Any]:
    """Load one Lead DB entry or fail closed."""

    for lead in db.get("leads", []):
        if str(lead.get("id")) == lead_id:
            return lead
    raise SystemExit(f"Lead not found: {lead_id}")


def load_economic_proof(
    path: Path,
    *,
    schema_path: Path | None = None,
) -> dict[str, Any]:
    """Load and schema-validate economic proof."""

    if not path.exists():
        raise SystemExit(f"Economic proof does not exist: {path}")
    proof = json.loads(path.read_text(errors="replace"))
    if not isinstance(proof, dict):
        raise SystemExit(f"Economic proof root must be an object: {path}")
    validate_economic_proof(proof, schema_path or economic_proof_schema_path())
    return proof


def line_number_for_offset(
    text: str,
    offset: int,
) -> int:
    """Return 1-indexed line number for a character offset."""

    return text.count("\n", 0, max(offset, 0)) + 1


def add_block(
    blocks: list[dict[str, Any]],
    *,
    rule: str,
    reason: str,
    field: str | None = None,
    phrase: str | None = None,
    line: int | None = None,
) -> None:
    """Append one normalized linter block."""

    row: dict[str, Any] = {"rule": rule, "phrase": phrase, "line": line, "reason": reason}
    if field is not None:
        row["field"] = field
    blocks.append(row)


def phrase_regex(phrase: str) -> re.Pattern[str]:
    escaped = r"\s+".join(re.escape(part) for part in phrase.split())
    return re.compile(rf"(?<![A-Za-z0-9]){escaped}(?![A-Za-z0-9])", re.IGNORECASE)


def lint_speculative_wording(
    text: str,
) -> list[dict[str, Any]]:
    """
    Block speculative phrases with exact phrase and line number.
    Whole phrase boundaries prevent matching 'may' inside unrelated words.
    """

    blocks: list[dict[str, Any]] = []
    spans: list[tuple[int, int]] = []
    for phrase in sorted(SPECULATIVE_PHRASES, key=len, reverse=True):
        for match in phrase_regex(phrase).finditer(text):
            start, end = match.span()
            if any(start < existing_end and end > existing_start for existing_start, existing_end in spans):
                continue
            spans.append((start, end))
            add_block(
                blocks,
                rule="speculative_wording",
                phrase=match.group(0),
                line=line_number_for_offset(text, start),
                reason="speculative wording blocks triager acceptance",
            )
    return sorted(blocks, key=lambda b: (b.get("line") or 0, str(b.get("phrase") or "")))


def extract_sections(
    text: str,
) -> dict[str, tuple[int, str]]:
    """
    Parse markdown headings into section name -> (start_line, section_text).
    """

    lines = text.splitlines()
    headings: list[tuple[int, str]] = []
    for idx, line in enumerate(lines, start=1):
        match = re.match(r"^\s{0,3}#{1,6}\s+(.+?)\s*$", line)
        if match:
            headings.append((idx, match.group(1).strip().lower()))
    sections: dict[str, tuple[int, str]] = {}
    for pos, (line_no, name) in enumerate(headings):
        next_line = headings[pos + 1][0] if pos + 1 < len(headings) else len(lines) + 1
        body = "\n".join(lines[line_no: next_line - 1])
        sections[name] = (line_no, body)
    return sections


def section_text(sections: dict[str, tuple[int, str]], *names: str) -> tuple[int | None, str]:
    for key, (line, body) in sections.items():
        if any(name in key for name in names):
            return line, body
    return None, ""


def find_required_field_lines(
    text: str,
) -> dict[str, int | None]:
    """
    Return line numbers for title, severity, CVSS, affected address, steps,
    forge command, USD impact, remediation, and CWE/SWC reference.
    """

    lines = text.splitlines()
    fields: dict[str, int | None] = {
        "title": None,
        "severity": None,
        "cvss": None,
        "affected_contract": None,
        "steps": None,
        "poc_command": None,
        "usd_impact": None,
        "remediation": None,
        "cwe_or_swc": None,
    }
    sections = extract_sections(text)
    for idx, line in enumerate(lines, start=1):
        if fields["title"] is None and re.match(r"^\s*#\s+\S+", line):
            fields["title"] = idx
        if fields["severity"] is None and re.search(r"\bSeverity\b\s*[:|-]\s*(Critical|High|Medium|Low|Informational)\b", line, re.I):
            fields["severity"] = idx
        if fields["cvss"] is None and re.search(r"CVSS:3\.[01]/", line, re.I) and re.search(r"\b(?:[0-9]|10)(?:\.[0-9])?\b", line):
            fields["cvss"] = idx
        if fields["affected_contract"] is None and re.search(r"0x[a-fA-F0-9]{40}", line):
            fields["affected_contract"] = idx
        if fields["poc_command"] is None and re.search(r"\bforge\s+test\b", line):
            fields["poc_command"] = idx
        if fields["usd_impact"] is None and extract_usd_amounts(line):
            fields["usd_impact"] = idx
        if fields["cwe_or_swc"] is None and re.search(r"\b(?:CWE|SWC)-\d+\b", line, re.I):
            fields["cwe_or_swc"] = idx

    _, steps = section_text(sections, "steps", "reproduce", "reproduction")
    if re.search(r"(?m)^\s*1\.\s+\S+", steps):
        fields["steps"] = next((i for i, line in enumerate(lines, start=1) if re.match(r"^\s*1\.\s+\S+", line)), None)
    rem_line, remediation = section_text(sections, "remediation", "recommendation", "fix")
    if rem_line is not None and len(remediation.strip()) >= 30 and not re.search(r"\b(fix it|add checks|be careful)\b", remediation, re.I):
        fields["remediation"] = rem_line
    return fields


def lint_required_fields(
    text: str,
    lead: dict[str, Any],
    poc_path: Path | None,
) -> list[dict[str, Any]]:
    """
    Block missing required report fields.
    """

    del lead, poc_path
    blocks: list[dict[str, Any]] = []
    fields = find_required_field_lines(text)
    required = {
        "title": "missing required field: vulnerability title",
        "severity": "missing required field: severity",
        "cvss": "missing required field: CVSS vector string",
        "affected_contract": "missing required field: affected contract address",
        "steps": "missing required field: steps to reproduce",
        "poc_command": "missing required field: proof of concept forge test command",
        "usd_impact": "missing required field: impact in USD",
        "remediation": "missing required field: remediation",
        "cwe_or_swc": "missing required field: CWE or SWC reference",
    }
    for field, reason in required.items():
        if fields.get(field) is None:
            add_block(blocks, rule="missing_required_field", field=field, phrase=None, line=None, reason=reason)
    return blocks


def extract_usd_amounts(
    text: str,
) -> list[tuple[int, Decimal]]:
    """Extract USD amounts with line numbers from report text."""

    amounts: list[tuple[int, Decimal]] = []
    pattern = re.compile(
        r"(?:\$\s*([0-9][0-9,]*(?:\.[0-9]+)?)|USD\s*([0-9][0-9,]*(?:\.[0-9]+)?)|([0-9][0-9,]*(?:\.[0-9]+)?)\s*USD)\b",
        re.I,
    )
    for match in pattern.finditer(text):
        raw = next(group for group in match.groups() if group)
        amounts.append((line_number_for_offset(text, match.start()), Decimal(raw.replace(",", ""))))
    return amounts


def proof_impact_usd(
    proof: dict[str, Any],
) -> Decimal:
    """Return max(protocol_loss_usd, bad_debt_usd) from economic proof."""

    impact = proof.get("impact") or {}
    return max(
        decimal_value(impact.get("protocol_loss_usd", "0"), "impact.protocol_loss_usd"),
        decimal_value(impact.get("bad_debt_usd", "0"), "impact.bad_debt_usd"),
    )


def lint_impact_section(
    text: str,
    proof: dict[str, Any],
    *,
    tolerance: Decimal = Decimal("0.05"),
) -> list[dict[str, Any]]:
    """
    Block missing USD impact, proof conflict ±5%, and generic impact text.
    """

    blocks: list[dict[str, Any]] = []
    sections = extract_sections(text)
    impact_line, impact = section_text(sections, "impact")
    impact_text = impact or text
    impact_amounts = extract_usd_amounts(impact_text)
    expected = proof_impact_usd(proof)
    if not impact_amounts:
        add_block(blocks, rule="missing_usd_impact", field="impact", line=impact_line, reason="missing USD impact")
    elif expected > 0:
        within = any(abs(amount - expected) / expected <= tolerance for _, amount in impact_amounts)
        if not within:
            add_block(
                blocks,
                rule="impact_conflicts_with_proof",
                field="impact",
                line=impact_amounts[0][0] if impact_line is None else impact_line,
                reason="impact amount conflicts with economic proof",
            )
    generic = re.search(r"funds\s+(?:could\s+be\s+)?lost", impact_text, re.I)
    if generic:
        add_block(
            blocks,
            rule="generic_impact_text",
            phrase=generic.group(0),
            line=(impact_line or 1) + impact_text[: generic.start()].count("\n"),
            reason="impact must state exact loss mechanism",
        )
    return blocks


def extract_forge_commands(
    text: str,
) -> list[tuple[int, str]]:
    """Return line-numbered forge test commands from report text."""

    commands: list[tuple[int, str]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        match = re.search(r"\bforge\s+test\b.*", line)
        if match:
            commands.append((idx, match.group(0).strip().strip("`")))
    return commands


def command_poc_paths(command: str) -> list[str]:
    return re.findall(r"(?:\./)?[A-Za-z0-9_./-]+\.t\.sol", command)


def lint_poc(
    text: str,
    *,
    report_path: Path | None = None,
    poc_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Block missing forge test command, nonexistent referenced file, and missing claimed PoC artifact.
    """

    blocks: list[dict[str, Any]] = []
    commands = extract_forge_commands(text)
    if not commands:
        add_block(blocks, rule="missing_poc_command", field="poc", line=None, reason="missing PoC command")
    if poc_path is not None:
        if not poc_path.exists():
            add_block(blocks, rule="poc_file_not_found", field="poc", phrase=str(poc_path), line=None, reason="PoC file not present at claimed path")
        return blocks
    base = report_path.parent if report_path is not None else Path.cwd()
    for line, command in commands:
        paths = command_poc_paths(command)
        for raw in paths:
            candidate = Path(raw)
            resolved = candidate if candidate.is_absolute() else base / candidate
            if not resolved.exists():
                add_block(blocks, rule="poc_file_not_found", field="poc", phrase=raw, line=line, reason="forge test command references nonexistent file")
    return blocks


def extract_severity(
    text: str,
) -> tuple[int | None, str | None]:
    """Return line and normalized severity."""

    for idx, line in enumerate(text.splitlines(), start=1):
        match = re.search(r"\bSeverity\b\s*[:|-]\s*(Critical|High|Medium|Low|Informational)\b", line, re.I)
        if match:
            value = match.group(1).lower()
            normalized = next(sev for sev in SEVERITIES if sev.lower() == value)
            return idx, normalized
    invalid = re.search(r"(?im)^.*\bSeverity\b\s*[:|-]\s*(\S+)", text)
    if invalid:
        return line_number_for_offset(text, invalid.start()), invalid.group(1)
    return None, None


def extract_cvss(
    text: str,
) -> tuple[int | None, str | None, Decimal | None]:
    """Return line, CVSS vector, and score if present."""

    vector_re = re.compile(r"CVSS:3\.[01]/[A-Z]{1,3}:[A-Z](?:/[A-Z]{1,3}:[A-Z]){3,}", re.I)
    for idx, line in enumerate(text.splitlines(), start=1):
        vector = vector_re.search(line)
        if not vector:
            continue
        prefix = line[: vector.start()]
        score_matches = re.findall(r"\b(10(?:\.0)?|[0-9](?:\.[0-9])?)\b", prefix)
        score = Decimal(score_matches[-1]) if score_matches else None
        return idx, vector.group(0), score
    return None, None, None


def minimum_allowed_severities(impact_usd: Decimal) -> set[str]:
    if impact_usd >= Decimal("100000"):
        return {"Critical"}
    if impact_usd >= Decimal("10000"):
        return {"Critical", "High"}
    if impact_usd >= Decimal("1000"):
        return {"Critical", "High", "Medium"}
    return set(SEVERITIES)


def lint_severity(
    text: str,
    proof: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Block invalid severity, malformed/missing CVSS, and proof-inconsistent severity.
    """

    blocks: list[dict[str, Any]] = []
    severity_line, severity = extract_severity(text)
    if severity is None:
        add_block(blocks, rule="missing_severity", field="severity", line=None, reason="missing severity")
    elif severity not in SEVERITIES:
        add_block(blocks, rule="invalid_severity", field="severity", phrase=severity, line=severity_line, reason="severity value is not accepted")
    cvss_line, cvss_vector, cvss_score = extract_cvss(text)
    if cvss_vector is None or cvss_score is None:
        add_block(blocks, rule="missing_or_malformed_cvss", field="cvss", line=cvss_line, reason="CVSS score missing or malformed")
    impact_usd = proof_impact_usd(proof)
    if severity in SEVERITIES and severity not in minimum_allowed_severities(impact_usd):
        add_block(blocks, rule="severity_inconsistent", field="severity", phrase=severity, line=severity_line, reason="severity inconsistent with economic proof")
    return blocks


def lint_evidence_bound_rules(text: str, lead: dict[str, Any], proof: dict[str, Any]) -> list[dict[str, Any]]:
    """Additional semantic blockers for evidence-bound Web3 reports."""

    blocks: list[dict[str, Any]] = []
    lower = text.lower()
    lines = text.splitlines()

    def first_line(pattern: str) -> int | None:
        for idx, line in enumerate(lines, start=1):
            if re.search(pattern, line, re.I):
                return idx
        return None

    if re.search(r"\b(scanner-only|only scanner|slither found|aderyn found)\b", text, re.I) and not re.search(r"\bmanual(?:ly)? verified\b", text, re.I):
        add_block(blocks, rule="scanner_only_finding", phrase="scanner-only", line=first_line(r"scanner|slither|aderyn"), reason="scanner-only findings cannot be submitted")
    if not re.search(r"\b(?:File|Path)\s*[:|-]\s*[^\n]+\.sol\b", text, re.I):
        add_block(blocks, rule="missing_file", field="file", line=None, reason="missing exact file path")
    if not re.search(r"\bFunction\s*[:|-]\s*[A-Za-z_][A-Za-z0-9_]*\b", text, re.I):
        add_block(blocks, rule="missing_function", field="function", line=None, reason="missing function name")
    if not re.search(r"\bLikelihood\s*[:|-]\s*\S+", text, re.I):
        add_block(blocks, rule="missing_likelihood", field="likelihood", line=None, reason="missing likelihood")
    if not re.search(r"\bAffected Asset\s*[:|-]\s*\S+", text, re.I):
        add_block(blocks, rule="missing_affected_asset", field="affected_asset", line=None, reason="missing affected asset")
    if re.search(r"\bAssum(?:e|ption|ptions)\b", text, re.I) and not re.search(r"\bAssumptions\s*[:|-]|##\s+Assumptions", text, re.I):
        add_block(blocks, rule="unlabeled_assumptions", field="assumptions", line=first_line(r"assum"), reason="unlabeled assumptions")
    sections = extract_sections(text)
    impact_line, impact_body = section_text(sections, "impact")
    impact_scope = impact_body or text
    if extract_usd_amounts(impact_scope) and not re.search(r"\b(economic proof|proof demonstrates|PoC demonstrates)\b", impact_scope, re.I):
        add_block(blocks, rule="unsupported_usd_impact", field="impact", line=impact_line or first_line(r"\$|USD"), reason="unsupported USD impact")
    if re.search(r"\bduplicate root cause\b", text, re.I) and not re.search(r"\bimpact differs\b", text, re.I):
        add_block(blocks, rule="duplicated_root_cause", phrase="duplicate root cause", line=first_line(r"duplicate root cause"), reason="duplicated root causes must be merged or impact-differentiated")
    if re.search(r"\bMEV\b.*\b(could|might|may|potentially|possibly)\b", text, re.I):
        add_block(blocks, rule="speculative_mev_claim", phrase="MEV", line=first_line(r"MEV"), reason="speculative MEV claims require ordered transaction sequence")
    if re.search(r"\b(cross-chain|bridge)\b.*\b(could|might|may|potentially|possibly)\b", text, re.I):
        add_block(blocks, rule="speculative_cross_chain_claim", phrase="cross-chain", line=first_line(r"cross-chain|bridge"), reason="speculative cross-chain claims require message lifecycle evidence")
    if re.search(r"\b(ignore|ignored|ignores|without considering)\b.*\b(modifier|modifiers|inherited check|inherited checks)\b", text, re.I):
        add_block(blocks, rule="ignored_modifier_claim", phrase="modifier", line=first_line(r"modifier|inherited check"), reason="findings cannot ignore modifiers or inherited checks")
    if re.search(r"\bmay be vulnerable\b", text, re.I) and not re.search(r"\b(PoC demonstrates|forge test|reproduction)\b", text, re.I):
        add_block(blocks, rule="may_be_vulnerable_without_evidence", phrase="may be vulnerable", line=first_line(r"may be vulnerable"), reason="'may be vulnerable' requires evidence")
    if re.search(r"\bcould lead to loss of funds\b", text, re.I) and not re.search(r"\bexploit path\b|\bSteps to Reproduce\b", text, re.I):
        add_block(blocks, rule="could_loss_without_path", phrase="could lead to loss of funds", line=first_line(r"could lead to loss of funds"), reason="loss-of-funds claim lacks exploit path")
    sev_line, severity = extract_severity(text)
    if severity == "Critical" and not re.search(r"\b(Attacker Capability|Exploit Path|Steps to Reproduce)\b", text, re.I):
        add_block(blocks, rule="critical_without_exploitability", field="severity", line=sev_line, reason="Critical severity requires realistic exploitability")
    if lead.get("source", {}).get("origin") == "scanner" and not re.search(r"\bmanual(?:ly)? verified\b", text, re.I):
        add_block(blocks, rule="scanner_output_not_validated", field="source", line=None, reason="scanner output was not manually validated")
    if proof_impact_usd(proof) <= 0 and extract_usd_amounts(text):
        add_block(blocks, rule="unsupported_usd_impact", field="impact", line=first_line(r"\$|USD"), reason="report states USD impact not supported by economic proof")
    return blocks


def lint_report(
    report_input: Path | dict[str, Any] | str,
    lead: dict[str, Any],
    proof: dict[str, Any],
    *,
    poc_path: Path | None = None,
    report_path: Path | None = None,
) -> dict[str, Any]:
    """
    Main pure linter.
    """

    text, _ = load_report(report_input)
    blocks: list[dict[str, Any]] = []
    blocks.extend(lint_speculative_wording(text))
    blocks.extend(lint_required_fields(text, lead, poc_path))
    blocks.extend(lint_impact_section(text, proof))
    blocks.extend(lint_poc(text, report_path=report_path, poc_path=poc_path))
    blocks.extend(lint_severity(text, proof))
    blocks.extend(lint_evidence_bound_rules(text, lead, proof))
    return {
        "status": "LINTER_PASS" if not blocks else "LINTER_BLOCK",
        "block_count": len(blocks),
        "blocks": blocks,
    }


def lint_report_file(
    report_path: Path,
    lead_db_path: Path,
    lead_id: str,
    economic_proof_path: Path,
    *,
    poc_path: Path | None = None,
    schema_path: Path | None = None,
) -> dict[str, Any]:
    """CLI/API entry point for markdown report linting."""

    db = load_lead_db(lead_db_path)
    lead = load_lead(db, lead_id)
    proof = load_economic_proof(economic_proof_path, schema_path=schema_path)
    return lint_report(report_path, lead, proof, poc_path=poc_path, report_path=report_path)


def lint_closure_report_draft(root: Path, candidate_id: str) -> dict[str, Any]:
    """Lint the post-hoc regression report draft without weakening normal report gates."""

    report_path = closure_path(root, candidate_id, "report_draft.md")
    package = load_json(closure_path(root, candidate_id, "final_evidence_package.json"), {})
    proof = package.get("economic_proof") or load_json(closure_path(root, candidate_id, "economic_proof.json"), {})
    text = report_path.read_text(errors="replace") if report_path.exists() else ""
    lower = text.lower()
    blocks: list[dict[str, Any]] = []
    if not report_path.exists():
        blocks.append({"rule": "missing_report_draft", "reason": "candidate_002_report_draft.md is missing"})
    for section in REQUIRED_REPORT_SECTIONS:
        if f"## {section.lower()}" not in lower:
            blocks.append({"rule": "missing_report_section", "field": section, "reason": f"missing required report section: {section}"})
    if "post-hoc patched-control regression" not in lower and "post-hoc regression evidence" not in lower:
        blocks.append({"rule": "missing_posthoc_label", "reason": "draft must state this is post-hoc patched-control regression evidence"})
    if "value at risk" not in lower or not package.get("value_at_risk"):
        blocks.append({"rule": "missing_value_at_risk", "field": "value_at_risk", "reason": "draft/final package must include value-at-risk"})
    theft_text = re.sub(r"\bnot\s+(?:a\s+)?(?:theft|stolen|steal|steals)\b", "", text, flags=re.I)
    theft_text = re.sub(r"\bno\s+(?:attacker\s+)?(?:theft|stolen|steal|steals)\b", "", theft_text, flags=re.I)
    if re.search(r"\b(theft|stolen|steal|steals)\b", theft_text, re.I) and proof.get("attacker_profit") is not True:
        blocks.append({"rule": "theft_claim_without_attacker_profit", "reason": "draft claims theft/stolen funds without attacker profit evidence"})
    if "production readiness" in lower and "does not change production readiness" not in lower and "not claim production readiness" not in lower:
        blocks.append({"rule": "production_readiness_claim", "reason": "draft must not imply production readiness"})
    if package.get("duplicate_known_issue_status") != "KNOWN_PATCHED_CONTROL" or "known issue status" not in lower:
        blocks.append({"rule": "missing_known_issue_note", "reason": "draft must state known patched-control status"})
    if str(package.get("poc_command") or "") not in text:
        blocks.append({"rule": "missing_exact_poc_command", "field": "poc_command", "reason": "draft must cite exact PoC command"})
    if package.get("counts_toward_readiness") is not False:
        blocks.append({"rule": "known_issue_counts_toward_readiness", "reason": "known patched-control evidence must not count toward readiness"})
    result = {
        "status": "LINTER_PASS" if not blocks else "LINTER_BLOCK",
        "candidate_id": candidate_id,
        "block_count": len(blocks),
        "blocks": blocks,
        "report_draft": str(report_path.relative_to(root)) if report_path.exists() else "missing",
        "report_ready_created": False,
        **safety_metadata(),
    }
    closure_path(root, candidate_id, "report_lint_result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def lint_repaired_report_draft(root: Path, candidate_id: str) -> dict[str, Any]:
    out_dir = root / "scoring" / "repaired_candidate_execution"
    report_path = out_dir / "repair_candidate_report_draft.md"
    package_path = out_dir / "repair_candidate_final_evidence_package.json"
    package = load_json(package_path, {})
    text = report_path.read_text(errors="replace") if report_path.exists() else ""
    lower = text.lower()
    blocks: list[dict[str, Any]] = []
    if not report_path.exists():
        blocks.append({"rule": "missing_report_draft", "reason": "repair_candidate_report_draft.md is missing"})
    if package.get("candidate_id") != candidate_id:
        blocks.append({"rule": "candidate_mismatch", "reason": "repaired final evidence package candidate mismatch"})
    if package.get("status") != "REPORT_READY_POSTHOC_SPENT_HOLDOUT":
        blocks.append({"rule": "missing_spent_holdout_status", "reason": "draft package must remain post-hoc spent holdout only"})
    if "post-hoc spent-holdout" not in lower and "post-hoc spent holdout" not in lower:
        blocks.append({"rule": "missing_posthoc_spent_holdout_label", "reason": "draft must state this is post-hoc spent-holdout evidence"})
    if "does not count toward readiness" not in lower and "counts toward readiness: false" not in lower:
        blocks.append({"rule": "missing_readiness_guard", "reason": "draft must state it does not count toward readiness"})
    if package.get("normal_bounty_report_ready") is not False or package.get("counts_toward_readiness") is not False:
        blocks.append({"rule": "spent_holdout_readiness_guard", "reason": "repaired spent-holdout package must not be normal report-ready or count toward readiness"})
    if str(package.get("poc_command") or "") not in text:
        blocks.append({"rule": "missing_exact_poc_command", "field": "poc_command", "reason": "draft must cite exact PoC command"})
    if any(phrase_regex(phrase).search(text) for phrase in ["could potentially", "possibly", "probably"]):
        blocks.append({"rule": "speculative_wording", "reason": "repaired draft contains speculative wording"})
    result = {
        "status": "LINTER_PASS" if not blocks else "LINTER_BLOCK",
        "candidate_id": candidate_id,
        "block_count": len(blocks),
        "blocks": blocks,
        "report_draft": str(report_path.relative_to(root)) if report_path.exists() else "missing",
        "report_ready_created": False,
        "normal_bounty_report_ready": False,
        "counts_toward_readiness": False,
        **safety_metadata(),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "repair_candidate_report_lint_result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def lint_expected_aligned_report_draft(root: Path, candidate_id: str) -> dict[str, Any]:
    out_dir = root / "scoring" / "fresh_v6_expected_aligned_execution"
    report_path = out_dir / "expected_aligned_report_draft.md"
    package_path = out_dir / "expected_aligned_evidence_package.json"
    package = load_json(package_path, {})
    text = report_path.read_text(errors="replace") if report_path.exists() else ""
    lower = text.lower()
    blocks: list[dict[str, Any]] = []
    if not report_path.exists():
        blocks.append({"rule": "missing_report_draft", "reason": "expected_aligned_report_draft.md is missing"})
    if package.get("candidate_id") != candidate_id:
        blocks.append({"rule": "candidate_mismatch", "reason": "expected-aligned evidence package candidate mismatch"})
    if package.get("status") != "CONFIRMED_POSTHOC_EXPECTED_ALIGNED_SPENT_HOLDOUT":
        blocks.append({"rule": "missing_expected_aligned_status", "reason": "draft package must remain expected-aligned post-hoc spent holdout only"})
    if "report_ready_posthoc_expected_aligned_spent_holdout" not in lower:
        blocks.append({"rule": "missing_posthoc_expected_aligned_label", "reason": "draft must state expected-aligned post-hoc spent-holdout status"})
    if "does not count toward readiness" not in lower and "counts toward readiness: false" not in lower:
        blocks.append({"rule": "missing_readiness_guard", "reason": "draft must state it does not count toward readiness"})
    if package.get("normal_bounty_report_ready") is not False or package.get("counts_toward_readiness") is not False:
        blocks.append({"rule": "spent_holdout_readiness_guard", "reason": "expected-aligned spent-holdout package must not be normal report-ready or count toward readiness"})
    if str(package.get("poc_command") or "") not in text:
        blocks.append({"rule": "missing_exact_poc_command", "field": "poc_command", "reason": "draft must cite exact PoC command"})
    if any(phrase_regex(phrase).search(text) for phrase in ["could potentially", "possibly", "probably"]):
        blocks.append({"rule": "speculative_wording", "reason": "expected-aligned draft contains speculative wording"})
    result = {
        "status": "LINTER_PASS" if not blocks else "LINTER_BLOCK",
        "candidate_id": candidate_id,
        "block_count": len(blocks),
        "blocks": blocks,
        "report_draft": str(report_path.relative_to(root)) if report_path.exists() else "missing",
        "report_ready_created": False,
        "normal_bounty_report_ready": False,
        "counts_toward_readiness": False,
        **safety_metadata(),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "expected_aligned_report_lint_result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Lint Immunefi-style Web3 bounty reports")
    parser.add_argument("report", nargs="?")
    parser.add_argument("lead_db", nargs="?")
    parser.add_argument("lead_id", nargs="?")
    parser.add_argument("economic_proof", nargs="?")
    parser.add_argument("--poc-path")
    parser.add_argument("--schema")
    parser.add_argument("--root", default="")
    parser.add_argument("--candidate", default="")
    parser.add_argument("--evidence-package", action="store_true")
    parser.add_argument("--report-draft", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.candidate and args.report_draft:
        root = Path(args.root) if args.root else Path(__file__).resolve().parents[1] / "benchmarks" / "public-historical-corpus"
        if args.candidate.startswith("EXPECTED-ALIGNED-"):
            result = lint_expected_aligned_report_draft(root, args.candidate)
        elif args.candidate.startswith("REPAIR-POC-"):
            result = lint_repaired_report_draft(root, args.candidate)
        else:
            result = lint_closure_report_draft(root, args.candidate)
        print(json.dumps(result, indent=2))
        return 0 if result["status"] == "LINTER_PASS" else 1
    if args.candidate and args.evidence_package:
        root = Path(args.root) if args.root else Path(__file__).resolve().parents[1] / "benchmarks" / "public-historical-corpus"
        package_path = root / "scoring" / "poc_vertical_slice_evidence_package.json"
        blocks = []
        if not package_path.exists():
            blocks.append({"rule": "missing_evidence_package", "reason": "poc_vertical_slice_evidence_package.json is missing"})
        else:
            evidence = json.loads(package_path.read_text(errors="replace"))
            for field in ["poc_result", "patched_regression_result", "recommended_fix", "confidence"]:
                if not evidence.get(field):
                    blocks.append({"rule": "missing_evidence_field", "field": field, "reason": f"evidence package missing {field}"})
        blocks.append({"rule": "no_report_draft", "reason": "no report draft was requested or created; evidence package is not REPORT_READY"})
        result = {"status": "LINTER_BLOCK", "candidate_id": args.candidate, "block_count": len(blocks), "blocks": blocks, "report_ready_created": False, "production_readiness_changed": False}
        (root / "scoring" / "poc_vertical_slice_linter_result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
        return 0
    if not (args.report and args.lead_db and args.lead_id and args.economic_proof):
        raise SystemExit("provide report lead_db lead_id economic_proof or --candidate --evidence-package")
    result = lint_report_file(
        Path(args.report),
        Path(args.lead_db),
        args.lead_id,
        Path(args.economic_proof),
        poc_path=Path(args.poc_path) if args.poc_path else None,
        schema_path=Path(args.schema) if args.schema else None,
    )
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "LINTER_PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
