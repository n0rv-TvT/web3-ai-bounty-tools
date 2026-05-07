# Lead Database Engine

Production component 1 of the Web3 audit engine.

## What It Does

The Lead Database is the system of record for every suspected vulnerability, from first scanner/x-ray signal to final `REPORT` or `KILL` decision. It converts the prompt stack into a stateful audit engine.

It stores:

- scope and target metadata
- every lead with status, score, evidence, impact, PoC state, validation gate, and kill/report reason
- links to artifacts: scanner outputs, x-ray files, on-chain probes, PoCs, reports
- deduplication groups and chain relationships
- status history for auditability

## How It Connects To Other Components

```text
Scope Manager        -> writes scope fields and accepted impact categories
Code Indexer         -> writes entrypoint/callgraph/storage artifact refs
Scanner Normalizer   -> imports normalized scanner rows as LEAD / CHAIN_REQUIRED / optional KILL rows
Hypothesis Engine    -> upgrades LEAD -> PROVE with exploit sentence/assertion target
On-Chain Verifier    -> attaches deployed-state artifact refs and value-at-risk evidence
PoC Builder          -> attaches PoC path/command/result and updates evidence level
Validator            -> writes strict 7-question gate verdict
Reporter             -> consumes only REPORT_READY/REPORT leads
Lead Memory          -> records final lessons from KILL/REPORT outcomes
```

## Tech Stack

- Storage format: JSON for portability and git diffability.
- Schema: JSON Schema draft 2020-12 in `schemas/lead_database.schema.json`.
- CLI: Python stdlib-first in `scripts/lead_db.py`; optional `jsonschema` package gives full schema validation.
- Default file path: `audit-leads.json` in the target repo root.

Why JSON instead of SQLite first: human-readable, easy to commit privately, simple to pass between agents. SQLite can be added later as a backend once the schema stabilizes.

## Lifecycle

Allowed practical lifecycle:

```text
INTAKE -> LEAD -> INVESTIGATING -> PROVE -> POC_READY -> VALIDATION_READY -> REPORT_READY -> REPORTED
                         \             \              \-> CHAIN_REQUIRED
                          \             \-> KILL
                           \-> KILL / DUPLICATE / OUT_OF_SCOPE / ACCEPTED_RISK
```

Status meanings:

- `INTAKE`: raw signal imported but not triaged.
- `LEAD`: interesting but not manually proven.
- `INVESTIGATING`: active manual trace.
- `PROVE`: exploit path is plausible; write PoC.
- `POC_READY`: PoC exists and should be run/reviewed.
- `VALIDATION_READY`: PoC passed; run strict validation gate.
- `REPORT_READY`: all validation questions passed.
- `REPORTED`: submitted or final report produced.
- `CHAIN_REQUIRED`: standalone impact weak; needs another condition/bug.
- `KILL`: no scope/reachability/impact/PoC or intended/duplicate/excluded.
- `DUPLICATE`: duplicate of another lead or public known issue.
- `OUT_OF_SCOPE`: affected code/address/impact outside program scope.
- `ACCEPTED_RISK`: docs/audits/program explicitly accept the behavior.

## Evidence Level

The schema records an integer `evidence.level` matching the evidence ladder:

0. raw signal only
1. scanner/grep/x-ray signal
2. manual source confirmation
3. normal attacker reachability
4. invariant violation or state transition traced
5. PoC written and runnable
6. PoC passed with assertions
7. scope/duplicate/intended behavior checked
8. report-ready

The validator refuses `REPORT_READY` or `REPORTED` unless the PoC passed and all seven validation questions are true.

## CLI Examples

Initialize:

```bash
python3 <skill-dir>/scripts/lead_db.py init audit-leads.json --target "Example Protocol" --protocol vault --repo .
```

Add a lead:

```bash
python3 <skill-dir>/scripts/lead_db.py add audit-leads.json \
  --title "Donation inflation in Vault.deposit" \
  --bug-class erc4626-inflation \
  --file src/Vault.sol --contract Vault --function deposit --line 120 \
  --exploit-sentence "Because the first depositor can donate before victim deposit..." \
  --impact-type stolen-funds
```

Import normalized scanner leads. Both canonical scanner reports and legacy lead arrays are accepted:

```bash
python3 <skill-dir>/scripts/lead_db.py import-scanner audit-leads.json normalized-scanner-report.json
# Optional: include suppressed KILL rows for auditability
python3 <skill-dir>/scripts/lead_db.py import-scanner audit-leads.json normalized-scanner-report.json --include-killed
```

List and validate:

```bash
python3 <skill-dir>/scripts/lead_db.py list audit-leads.json --status LEAD
python3 <skill-dir>/scripts/lead_db.py metrics audit-leads.json
python3 <skill-dir>/scripts/lead_db.py validate audit-leads.json
```

Attach PoC result:

```bash
python3 <skill-dir>/scripts/lead_db.py add-poc audit-leads.json L-0001 \
  --path test/VaultInflation.t.sol \
  --command "forge test --match-test test_exploit -vvvv" \
  --status PASS \
  --summary "attackerGain == victimLoss == 100e18"
```

Generate a Foundry scaffold from a `PROVE` lead before filling the exploit:

```bash
python3 <skill-dir>/scripts/foundry_poc_generator.py \
  --project-root . \
  --lead-db audit-leads.json \
  --lead-id L-0001 \
  --onchain onchain.json \
  --code-index x-ray/code-index.json \
  --out test/L0001Exploit.t.sol \
  --metadata test/L0001Exploit.plan.json
```

Generated scaffolds should be recorded as `PLANNED` at most. Use `PASS` only after the test passes and asserts concrete impact.

Run the strict validation gate and promote only after all seven answers are true and PoC status is `PASS`:

```bash
python3 <skill-dir>/scripts/lead_db.py set-gate audit-leads.json L-0001 \
  --in-scope \
  --reachable \
  --normal-attacker \
  --normal-victim \
  --concrete-impact \
  --working-poc \
  --duplicate-intended-checked \
  --promote
```

Use `/web3-leads` from Opencode to initialize, import, list, update, validate, and summarize the same database without memorizing the CLI flags.

## Production Rules

- Do not store secrets, private keys, seed phrases, RPC keys, or private user data.
- Every status transition must append `status_history`.
- Every scanner item starts as `LEAD`, `INTAKE`, `CHAIN_REQUIRED`, or suppressed `KILL`, never `REPORT`.
- `KILL` requires a kill reason.
- `REPORT_READY` requires PoC pass + validation gate pass.
- `duplicate_of` must point to an existing lead.
- `metrics` are derived from `leads`; recompute with `lead_db.py metrics --write` when editing JSON manually.
