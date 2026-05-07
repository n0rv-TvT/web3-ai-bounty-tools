---
description: Run Web3 access control audit lens
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Run only the access-control lens on `$ARGUMENTS`.

Map every sensitive state writer and compare guards across siblings. Focus on missing modifiers, inline sender checks, role escalation, initialization, upgrades, confused deputy calls, delegatecall, and proxy authority.

Return concrete unauthorized actions only. Do not report admin-does-admin-things.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-access
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
  target: "<program/repo/contract>"
  summary: "<one sentence>"
  leads:
    - id: "<lead id>"
      status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
      source_pointer: "<file:contract:function>"
      unauthorized_action: "<state change or role action>"
      guard_delta: "<missing/mismatched guard>"
      impact_claim: "<accepted impact or why weak>"
      evidence_missing: []
      next_action: "<exact command or stop reason>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
