---
description: Build cross-file Web3 assumption ledger
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first.

Target:

`$ARGUMENTS`

Build an assumption ledger:

```text
Assumption:
Made in:
Relied on by:
Violated by:
Impact if false:
Status: LEAD | PROVE | CHAIN_REQUIRED | NEEDS_CONTEXT | NEEDS_SCOPE_CONFIRMATION | NA_RISK | KILL
```

Focus on cross-file assumptions involving interfaces, accounting, roles, callbacks, oracle inputs, signatures, bridge messages, and AI/tool boundaries.

Return top assumptions that deserve `/web3-hypothesize` or `/web3-poc`.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-assumptions
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: LEAD|PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
  target: "<program/repo/contract>"
  summary: "<one sentence>"
  assumptions:
    - id: "A-01"
      status: LEAD|PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
      made_in: "<file:contract:function>"
      relied_on_by: "<file:contract:function>"
      violated_by: "<file:contract:function or condition>"
      impact_if_false: "<accepted impact or why weak>"
      evidence_missing: []
      next_action: "<exact command or stop reason>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
