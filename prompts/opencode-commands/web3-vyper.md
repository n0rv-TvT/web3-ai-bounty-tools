---
description: Run Vyper-specific Web3 audit module
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow the Vyper section of `LANGUAGE_MODULES.md`.

Target:

`$ARGUMENTS`

Focus on `@external`/`@internal` visibility, `@nonreentrant` lock coverage, `raw_call`, decimal math, storage layout, external-call ordering, sentinel addresses, and ERC20 return handling.

Return canonical-status leads with exact PoC/test recommendations.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-vyper
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
  target: "<program/repo/contract>"
  summary: "<one sentence>"
  vyper_leads:
    - id: "<lead id>"
      status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
      source_pointer: "<file:contract:function>"
      risk_construct: "<visibility/nonreentrant/raw_call/math/storage/etc>"
      impact_claim: "<accepted impact or why weak>"
      evidence_missing: []
      next_action: "<exact command or stop reason>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
