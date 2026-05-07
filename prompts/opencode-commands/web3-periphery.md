---
description: Run Web3 periphery/helper audit lens
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Run only the periphery lens on `$ARGUMENTS`.

Prioritize small libraries, encoders/decoders, wrappers, abstract bases, provider adapters, assembly helpers, existence checks, and return-value assumptions that core contracts trust.

Return caller impact, not isolated helper style issues.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-periphery
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
  target: "<program/repo/contract>"
  summary: "<one sentence>"
  periphery_leads:
    - id: "<lead id>"
      status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
      source_pointer: "<file:library/helper:function>"
      trusted_by: "<caller/core path>"
      broken_assumption: "<assumption>"
      caller_impact: "<accepted impact or why weak>"
      evidence_missing: []
      next_action: "<exact command or stop reason>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
