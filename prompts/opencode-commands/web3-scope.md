---
description: Build or review a structured Web3 target scope and impact brief before hunting
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow `SCOPE_TARGET_BRIEF.md`.

Target or program scope:

`$ARGUMENTS`

## Purpose

Create or review a structured `target-scope.json` / `audit-notes/target-scope.json` style brief so later hunting, validation, duplicate checks, and reports use explicit in-scope assets, accepted impacts, exclusions, target version, and testing permissions.

Do not run a live audit target, broadcast transactions, use RPC, or fetch private platform data unless explicitly authorized. If scope evidence is incomplete, mark `NEEDS_CONTEXT` or `NEEDS_SCOPE_CONFIRMATION` and ask for the missing scope text.

## Required extraction

Extract or confirm:

- selected severity mode
- program/target name
- repo/source path and commit/tag
- protocol types
- in-scope chains, addresses, proxy/implementation addresses, source paths
- in-scope and out-of-scope assets/tokens
- accepted impacts, copied verbatim when available
- excluded impacts, copied verbatim when available
- local/fork/RPC/live transaction testing permissions
- admin/operator recovery assumptions and privileged roles
- crown jewels and value-at-risk notes
- prior audits/reports/changelog/known limitations
- open questions and scope blockers

## Output

Return this parseable block first:

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
  target_scope:
    schema_version: web3-target-scope/v1
    status: PROVE|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE
    target:
      program: "<name>"
      repo: "<repo/path>"
      commit_or_tag: "<commit/tag/unknown>"
      protocol_types: []
      source_of_truth: []
      scope_confidence: confirmed|partial|unknown
    chains: []
    contracts: []
    assets:
      in_scope_tokens: []
      out_of_scope_tokens: []
      value_at_risk_notes: "<notes>"
      tvl_usd_estimate: null
    accepted_impacts: []
    excluded_impacts: []
    testing_permissions:
      local_tests_allowed: true
      fork_tests_allowed: true|false|unknown
      read_only_rpc_allowed: true|false|unknown
      live_transactions_allowed: true|false|unknown
      broadcast_allowed: true|false
      mainnet_testing_notes: "<notes>"
    privileged_roles_and_recovery: []
    crown_jewels: []
    known_limitations: []
    prior_audits_or_reports: []
    open_questions: []
    scope_blockers: []
    next_action: "<exact command or stop reason>"
```

Only use `status: PROVE` when scope is sufficient to continue local/source hunting. This does not mean any finding is report-ready.
