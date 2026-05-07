# Code Index Engine

Production component 2 of the Web3 audit engine.

## What It Does

The Code Index Engine creates a machine-readable Solidity audit index before manual hunting. It maps source files, contracts, storage declarations, public/external functions, modifiers, read/write sites, call edges, value movement, auth checks, and risk signals.

It is not a scanner verdict system. It produces structured lead-generation facts so the auditor can ask better questions:

- Which public functions move assets?
- Which storage variables have multiple writer paths?
- Which functions share accounting variables but have different modifiers?
- Where do external calls, delegatecalls, signature recovery, oracle reads, or initializers appear?
- Which risk signals should become Lead Database entries and which should be killed quickly?

## Files

- CLI: `scripts/code_indexer.py`
- JSON Schema: `schemas/code_index.schema.json`
- Default output: `x-ray/code-index.json`
- Lead DB artifact type: `code-index`

The parser is stdlib-only and heuristic. It preserves line numbers, handles nested braces well enough for normal Solidity, and avoids claiming vulnerabilities. When precision is required, cross-check with compiler AST tools (`forge inspect`, `solc --ast-compact-json`, Slither, Wake, or Surya).

## Index Contents

Top-level fields:

- `source_files`: path, hash, line count, imports.
- `contracts`: kind, bases, state variables, modifiers, functions, events, errors.
- `storage_index`: variables, writer functions, reader functions, multiple-writer storage.
- `callgraph`: internal and external/low-level edges.
- `risk_signals`: lead templates for interesting patterns.
- `metrics`: counts for quick triage.

Function facts include:

- visibility and state mutability
- modifiers and inline auth checks
- parameters and returns
- state reads/writes and write snippets
- external calls, low-level calls, internal calls
- incoming/outgoing asset flow
- emitted events, revert predicates, contract creation
- risk tags such as `permissionless-value-out`, `delegatecall`, `signature-replay-signal`, `oracle-freshness-signal`, `initializer-without-initializer-modifier`, and `external-call-before-state-write`

Storage facts include:

- type, visibility, qualifiers, initializer
- approximate `slot_order_hint` for persistent variables
- sensitive tags for accounting, roles, oracle, nonce, signer, supply, balance, reward, and debt state
- writer/reader fan-in for sibling-path comparison

## Commands

Build an index for the current repo:

```bash
python3 <skill-dir>/scripts/code_indexer.py . --out x-ray/code-index.json
```

Build from a specific source directory:

```bash
python3 <skill-dir>/scripts/code_indexer.py . --src-dir contracts --out x-ray/code-index.json
```

Include tests/mocks/scripts when auditing harnesses or deployment logic:

```bash
python3 <skill-dir>/scripts/code_indexer.py . --include-tests --out x-ray/code-index.full.json
```

Print full JSON to stdout:

```bash
python3 <skill-dir>/scripts/code_indexer.py . --json
```

Attach the index to the Lead Database:

```bash
python3 <skill-dir>/scripts/lead_db.py add-artifact audit-leads.json \
  --type code-index \
  --path x-ray/code-index.json \
  --tool code_indexer.py \
  --command "python3 <skill-dir>/scripts/code_indexer.py . --out x-ray/code-index.json" \
  --summary "contract/function/storage/callgraph index for audit triage"
```

Validate the produced artifact when `jsonschema` is available:

```bash
python3 - <<'PY'
import json, jsonschema
schema=json.load(open('<skill-dir>/schemas/code_index.schema.json'))
data=json.load(open('x-ray/code-index.json'))
jsonschema.Draft202012Validator(schema).validate(data)
print('code index validation passed')
PY
```

## How To Use The Index

1. Sort public/external functions by value movement.
2. For each value-moving function, inspect its sibling functions and modifier differences.
3. Review `storage_index.variables_with_multiple_writers` for accounting variables with uneven writer paths.
4. Review risk signals and create Lead DB entries only when the signal has a plausible accepted impact path.
5. Convert a signal into a concrete exploit sentence before PoC work.
6. Kill signals that are admin-only, intended behavior, dead code, scanner-only, or lack concrete impact.

## Lead Templates

Risk signals include `lead_template` strings. Use them as starting points, not reports. A good promoted lead must become:

```text
Because <normal attacker> can reach <function> while <state/assumption> is stale/missing/desynced, the attacker can <steps> causing <accepted impact>.
```

## Production Rules

- Do not report code-index signals as findings.
- Do not trust regex extraction for final proof; manually verify source and, for deployed targets, bytecode/version.
- Do not treat `slot_order_hint` as an exact storage layout for packed variables, inherited storage, or compiler-specific layouts. Use `forge inspect <Contract> storage-layout` for exact slots.
- Use the callgraph to prioritize paths, then read the code around each edge.
- Every index artifact should be linked in `audit-leads.json` as `code-index`.
