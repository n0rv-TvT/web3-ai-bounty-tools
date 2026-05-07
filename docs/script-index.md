# Script Index

Reusable scripts live under `skills/web3-ai-bounty/scripts/`.

## Safety and gate scripts

| Script | Purpose |
|---|---|
| `safety_guard.py` | Safety self-tests and guard checks |
| `poc_execution_gate.py` | Gate local PoC execution and block unsafe runs |
| `readiness_policy.py` | Enforce report-readiness and post-hoc evidence policy |
| `no_overfit_guard.py` | Guard against benchmark leakage and overfit claims |
| `pipeline_enforcer.py` | Enforce final evidence/report pipeline status |

## Evidence and report scripts

| Script | Purpose |
|---|---|
| `evidence_package_builder.py` | Build evidence packages from finding artifacts |
| `evidence_package_validator.py` | Validate required evidence fields |
| `final_evidence_package_builder.py` | Build final evidence packages |
| `report_draft_builder.py` | Build report drafts from evidence |
| `report_linter.py` | Lint report wording and safety claims |
| `duplicate_known_issue_reviewer.py` | Check duplicate/known-issue risk |
| `intended_behavior_reviewer.py` | Check intended-behavior risk |

## PoC scripts

| Script | Purpose |
|---|---|
| `foundry_poc_generator.py` | Generate Foundry PoC scaffolds/plans |
| `executable_poc_generator.py` | Generate executable local PoC structures |
| `poc_candidate_selector.py` | Select PoC-ready candidates |
| `poc_autofill.py` | Assist with PoC filling |
| `assertion_synthesizer.py` | Suggest meaningful exploit assertions |

## Code and lead analysis scripts

| Script | Purpose |
|---|---|
| `code_indexer.py` | Build a source-code index |
| `entrypoint_scan.py` | Enumerate public/external entry points |
| `invariant_extract.py` | Extract candidate invariants |
| `protocol_xray.py` | Produce protocol x-ray style summaries |
| `source_to_lead_converter.py` | Convert source signals into leads |
| `bounty_hypothesis_engine.py` | Generate exploit hypotheses |
| `lead_db.py` | Track leads and finding lifecycle |

## Scanner/on-chain helpers

| Script | Purpose |
|---|---|
| `scanner_normalize.py` | Normalize scanner JSON into structured leads |
| `onchain_verify.py` | Read-only on-chain verification helper |
| `onchain_probe.py` | Read-only probe helper |

Use scripts only on authorized targets or local toy fixtures. Do not commit raw outputs containing secrets, RPC URLs, cookies, or private target data.
