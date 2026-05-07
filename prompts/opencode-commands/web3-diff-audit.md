---
description: Audit recent Solidity/Web3 changes for security regressions
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Audit the recent diff or specified range:

`$ARGUMENTS`

If no range is supplied, inspect unstaged, staged, and recent committed changes.

Focus on:

- New or changed external/public functions.
- Modifier, role, pause, epoch, and initializer changes.
- Accounting variable updates and ordering.
- Oracle source, staleness, confidence, or TWAP changes.
- Token transfer and external call ordering.
- Signature domain, nonce, deadline, and chain binding changes.
- AI agent tool permission, prompt, signing, and transaction submission changes.

Return findings first, ordered by severity, with file/function references. If no findings, state residual risk and missing tests.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-diff-audit
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: LEAD|PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|DUPLICATE|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
  target: "<repo/range>"
  summary: "<one sentence>"
  diff_range: "<range or working tree>"
  changed_security_surfaces: []
  leads:
    - id: "<lead id>"
      status: LEAD|PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|DUPLICATE|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
      source_pointer: "<file:contract:function>"
      changed_assumption: "<what changed>"
      impact_claim: "<accepted impact or why weak>"
      proof_needed: "<test/assertion>"
      next_action: "<exact command or stop reason>"
  residual_risk: "<summary>"
  missing_tests: []
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
