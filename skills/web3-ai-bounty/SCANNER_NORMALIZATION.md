# Scanner Normalization Engine

Production component 3 of the Web3 audit engine.

## Purpose

Scanner output is useful only when it becomes structured lead data. This engine ingests noisy scanner JSON/SARIF, maps detector names into a bounty-oriented bug taxonomy, enriches rows with Code Index context, suppresses known non-bounty noise, deduplicates repeated signals, and emits Lead Database-ready rows.

It never emits findings. Every non-suppressed row remains evidence level 1 until manually proven with reachability, concrete impact, and PoC assertions.

## Files

- CLI: `scripts/scanner_normalize.py`
- JSON Schema: `schemas/normalized_scanner.schema.json`
- Example scanner input: `examples/slither_results.example.json`
- Example canonical output: `examples/normalized_scanner_report.example.json`
- Example legacy Lead DB rows: `examples/normalized_scanner_leads.example.json`
- Lead DB import command: `scripts/lead_db.py import-scanner`

## Supported Inputs

First-class parsers:

- Slither JSON: `slither . --json slither-results.json`
- Semgrep JSON: `semgrep --json ...`
- Mythril/MythX-style JSON
- SARIF 2.1.0

Tolerant generic parser:

- Aderyn JSON-like output
- Wake/Solhint/custom scanner JSON
- generic `issues`, `findings`, `results`, `detectors`, `vulnerabilities`, severity buckets

## Canonical Output

The canonical report is an object:

```json
{
  "schema_version": "1.0.0",
  "generated_at": "2026-05-06T00:00:00Z",
  "inputs": [{ "path": "slither-results.json", "sha256": "...", "tool": "slither", "raw_count": 12 }],
  "normalizer": { "dedupe": true, "include_killed_in_leads": false, "code_index": "x-ray/code-index.json" },
  "summary": { "raw_count": 12, "normalized_count": 7, "lead_count": 3, "killed_count": 4 },
  "leads": [],
  "suppressed": []
}
```

Each lead contains:

- `tool` / `tools`
- raw `rule_id`, title, message
- canonical `bug_class`, `category`, `severity`, `confidence`
- `status`: `LEAD`, `CHAIN_REQUIRED`, or `KILL`
- `triage_verdict`
- file/line/contract/function
- `impact_type` and `impact_hint`
- `proof_needed` and `proof_questions`
- `exploit_hypothesis`
- deterministic `dedupe_key`, `group_key`, and `fingerprint`
- Code Index context when available: visibility, value movement, auth checks, writes, reads, risk tags
- score fields compatible with Lead DB
- raw excerpt for auditability

Schema validation:

```bash
python3 - <<'PY'
import json, jsonschema
schema=json.load(open('<skill-dir>/schemas/normalized_scanner.schema.json'))
data=json.load(open('normalized-scanner-report.json'))
jsonschema.Draft202012Validator(schema).validate(data)
print('normalized scanner validation passed')
PY
```

## Commands

Normalize one scanner output:

```bash
python3 <skill-dir>/scripts/scanner_normalize.py slither-results.json \
  --tool auto \
  --json normalized-scanner-report.json
```

Normalize and enrich with the Code Index:

```bash
python3 <skill-dir>/scripts/code_indexer.py . --out x-ray/code-index.json
python3 <skill-dir>/scripts/scanner_normalize.py slither-results.json semgrep.json \
  --tool auto \
  --code-index x-ray/code-index.json \
  --json normalized-scanner-report.json \
  --leads-json normalized-scanner-leads.json
```

Import into Lead DB. Canonical reports and legacy lead arrays are both accepted:

```bash
python3 <skill-dir>/scripts/lead_db.py import-scanner audit-leads.json normalized-scanner-report.json
```

By default, suppressed `KILL` rows are not imported. Import them for auditability only when desired:

```bash
python3 <skill-dir>/scripts/lead_db.py import-scanner audit-leads.json normalized-scanner-report.json --include-killed
```

Attach scanner artifacts to Lead DB:

```bash
python3 <skill-dir>/scripts/lead_db.py add-artifact audit-leads.json \
  --type scanner \
  --path normalized-scanner-report.json \
  --tool scanner_normalize.py \
  --command "python3 <skill-dir>/scripts/scanner_normalize.py slither-results.json --code-index x-ray/code-index.json --json normalized-scanner-report.json"
```

## Taxonomy Mapping

Scanner names are mapped into exploit-oriented classes:

- `reentrancy-or-callback-ordering`
- `arbitrary-asset-transfer`
- `controlled-delegatecall`
- `unchecked-call-or-token-return`
- `access-control-mismatch`
- `proxy-or-initialization-bug`
- `signature-replay-or-domain-bypass`
- `oracle-price-manipulation-or-staleness`
- `erc4626-or-share-accounting`
- `math-precision-or-overflow`
- `tx-origin-authentication`
- `weak-randomness-or-time-dependence`
- fallback: `scanner-signal`

The taxonomy is intentionally bounty-focused. A detector is valuable only if it can plausibly reach stolen funds, frozen funds, bad debt, unauthorized privileged action, account takeover, sensitive data exposure, or unsafe signing/tool execution.

## Suppression Rules

Known non-bounty scanner noise is marked `KILL` with a suppression reason:

- naming/style issues
- compiler pragma/version warnings without exploit path
- `could be constant` / `could be immutable`
- gas optimizations
- unused/dead code signals without reachability
- documentation/license/conformance-only issues
- generic informational signals with no mapped high-impact class

Suppression is not final if the Code Index shows a mapped high-impact class on a value-moving path. In that case the row remains a `LEAD`.

## Required Triage For Every Non-Suppressed Lead

Ask before promoting out of `LEAD`:

1. Is the line reachable by a normal attacker or accepted role?
2. Is the affected contract/function in current deployed or in-scope source?
3. Does the code path move funds, create bad debt, freeze funds, corrupt privileged state, leak data, or trigger unsafe signing/tool execution?
4. What exact invariant breaks?
5. Can a minimal PoC assert attacker gain, victim/protocol loss, bad debt, frozen funds, or unauthorized state change?
6. Do docs/prior audits/exclusions make this intended, duplicate, or out of scope?

If no, mark `KILL` or `CHAIN_REQUIRED` in Lead DB.

## Prioritization Signals

Prioritize scanner rows that overlap with:

- Code Index `value_moving = true`
- public/external reachability
- multiple scanner tools hitting the same `dedupe_key`
- sensitive storage with multiple writers
- x-ray invariant gaps
- recent git-risk hotspots
- known paid-bug shapes
- deployed contracts with value at risk

Do not prioritize:

- scanner-only style issues
- best-practice warnings without exploit path
- admin-only findings unless the bug is privilege bypass
- dead/test/mock code unless explicitly in scope
- MEV/frontrunning/timestamp warnings unless the program accepts them and impact is deterministic

## Output Discipline

- `LEAD`: manually trace and try to build exploit sentence.
- `CHAIN_REQUIRED`: weak standalone; needs another bug, victim action, or economic condition.
- `KILL`: suppressed noise, no reachability, no concrete impact, out of scope, or intended behavior.
- Never output `REPORT_READY` from scanner normalization.
