---
description: Find sibling function and modifier inconsistencies in Solidity code
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Use the `web3_audit` MCP sibling modifier report and modifier matrix against:

`$ARGUMENTS`

If no target is supplied, use the current repository.

Focus on sibling families:

- `deposit`, `mint`, `withdraw`, `redeem`
- `stake`, `unstake`, `claim`, `harvest`, `compound`
- `vote`, `poke`, `reset`, `attach`, `detach`
- `create`, `update`, `cancel`, `fill`
- `initialize`, `upgradeTo`, `setImplementation`
- `set*` and `update*` admin functions

Return modifier mismatches first. For each mismatch, explain whether it likely matters and what PoC would prove impact.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-siblings
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: LEAD|PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
  target: "<program/repo/contract>"
  summary: "<one sentence>"
  modifier_mismatches:
    - id: "<lead id>"
      status: LEAD|PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
      sibling_family: "<deposit/mint/etc>"
      protected_function: "<file:contract:function>"
      weaker_function: "<file:contract:function>"
      guard_delta: "<missing/mismatched modifier/check>"
      impact_claim: "<accepted impact or why weak>"
      proof_needed: "<PoC assertion target>"
      next_action: "<exact command or stop reason>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
