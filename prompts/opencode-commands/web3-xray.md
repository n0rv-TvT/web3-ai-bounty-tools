---
description: Generate Web3 pre-audit x-ray artifacts
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow `X_RAY_PREAUDIT_WORKFLOW.md`. Use the local helper scripts in `scripts/` when available.

Target: `$ARGUMENTS`

If no target is supplied, use the current repository.

Generate lead-generation artifacts, not findings:

1. Enumerate source, tests, docs, deployment scripts, and configs.
2. Build `x-ray/code-index.json` with contracts, storage, functions, modifiers, callgraph edges, and risk signals.
3. Classify permissionless, role-gated, admin, and initializer entry points.
4. Build value-moving flow paths.
5. Synthesize guard, single-contract, cross-contract, and economic invariants.
6. Map architecture and external dependencies.
7. Extract docs/spec assumptions.
8. Inspect git-risk signals and recent dangerous-area changes.
9. Output top `LEAD` items that should feed `/web3-hunt` or `/web3-hypothesize`.

Do not report x-ray observations as vulnerabilities without PoCs.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-xray
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: LEAD|PROVE|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|KILL|AUDIT_NOTE|LOW_INFO
  target: "<program/repo>"
  summary: "<one sentence>"
  artifacts:
    code_index: "x-ray/code-index.json|not_written"
    entrypoints: "x-ray/entrypoints.json|not_written"
    invariants: "x-ray/invariants-raw.json|not_written"
    git_risk: "x-ray/git-risk.json|not_written"
  top_leads:
    - id: "<lead id>"
      status: LEAD|PROVE|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|KILL|AUDIT_NOTE|LOW_INFO
      source_pointer: "<file:contract:function>"
      risk_signal: "<signal>"
      proof_needed: "<proof needed>"
      next_action: "<exact command or stop reason>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
