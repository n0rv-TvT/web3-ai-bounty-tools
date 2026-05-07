# Scope And Target Brief Schema

Use this before hunting, PoC work, validation, and report drafting. A Web3 lead cannot become `REPORT_READY` unless scope, accepted impact, excluded impact, target version, and testing permissions are explicit.

The scope artifact is usually `target-scope.json` in the target repo root or `audit-notes/target-scope.json` when the repo should stay clean.

Validate a written scope artifact with:

```bash
python3 <skill-dir>/scripts/schema_validator.py target_scope target-scope.json
```

## Safety Rules

- Do not test public assets or deployed contracts until the program/scope authorizes it.
- Do not broadcast transactions unless explicitly authorized.
- Do not store cookies, API keys, private reports, triager comments, private platform URLs, RPC secrets, seed phrases, or private keys in the scope artifact.
- If scope is unknown, operate only on local source and return `NEEDS_SCOPE_CONFIRMATION` before live/on-chain actions or report drafting.
- Copy accepted impact and exclusions verbatim when available. Do not paraphrase away important limits.

## Required Scope Artifact

```json
{
  "schema_version": "web3-target-scope/v1",
  "status": "NEEDS_CONTEXT",
  "severity_mode": "critical-bounty",
  "target": {
    "program": "",
    "repo": "",
    "commit_or_tag": "",
    "protocol_types": [],
    "source_of_truth": [],
    "scope_confidence": "unknown"
  },
  "chains": [
    {
      "name": "",
      "chain_id": null,
      "in_scope": true,
      "notes": ""
    }
  ],
  "contracts": [
    {
      "name": "",
      "address": "",
      "chain_id": null,
      "proxy_address": "",
      "implementation_address": "",
      "source_path": "",
      "in_scope": true,
      "scope_basis": ""
    }
  ],
  "assets": {
    "in_scope_tokens": [],
    "out_of_scope_tokens": [],
    "value_at_risk_notes": "",
    "tvl_usd_estimate": null
  },
  "accepted_impacts": [
    {
      "category": "",
      "verbatim_text": "",
      "severity": "critical|high|medium|low|unknown",
      "conditions": []
    }
  ],
  "excluded_impacts": [
    {
      "category": "",
      "verbatim_text": "",
      "notes": ""
    }
  ],
  "testing_permissions": {
    "local_tests_allowed": true,
    "fork_tests_allowed": "unknown",
    "read_only_rpc_allowed": "unknown",
    "live_transactions_allowed": false,
    "broadcast_allowed": false,
    "mainnet_testing_notes": ""
  },
  "privileged_roles_and_recovery": [
    {
      "role": "",
      "capabilities": [],
      "recovery_or_pause_assumptions": "",
      "scope_relevance": ""
    }
  ],
  "crown_jewels": [],
  "known_limitations": [],
  "prior_audits_or_reports": [],
  "open_questions": [],
  "scope_blockers": [],
  "next_action": ""
}
```

## Status Rules

- `PROVE`: scope is sufficient to hunt locally and identify PoC-ready leads. This is not finding readiness.
- `NEEDS_CONTEXT`: required scope fields are missing.
- `NEEDS_SCOPE_CONFIRMATION`: affected chain, contract, asset, impact, or testing permission is uncertain.
- `NA_RISK`: likely excluded or below selected severity mode.
- `KILL`: target is out of scope or not worth work under user constraints.
- `AUDIT_NOTE`: audit-review mode only; scope permits notes but not bounty claims.

Do not use `REPORT_READY` from `/web3-scope`; scope can only unblock later validation.

## Minimum Fields Before Hunting

Before `/web3-hunt`, require at least:

- program or target name
- repo/source path or target component
- selected severity mode
- protocol type guess
- accepted impact categories or explicit statement that they are unknown
- exclusions or explicit statement that they are unknown
- local testing permission
- whether live transactions/broadcasts are forbidden

If accepted impacts or exclusions are unknown, keep hunting local/source-only and mark report/validation paths `NEEDS_SCOPE_CONFIRMATION` until scope is confirmed.

## Minimum Fields Before `REPORT_READY`

Before `/web3-validate` can return `REPORT_READY`, require:

- exact affected contract/function is in scope
- chain/address/source commit is in scope or target is source-only contest scope
- affected asset is in scope
- claimed impact matches an accepted category and conditions
- exclusions do not apply
- testing method is allowed
- duplicate/intended-behavior check is `CLEAR`

## Output Schema For `/web3-scope`

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-scope
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE
  target: "<program/repo/contract>"
  summary: "<one sentence>"
  scope_artifact: "target-scope.json|audit-notes/target-scope.json|not_written"
  scope_confidence: confirmed|partial|unknown
  accepted_impacts_count: 0
  excluded_impacts_count: 0
  live_testing_allowed: true|false|unknown
  broadcast_allowed: true|false
  blockers: []
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
