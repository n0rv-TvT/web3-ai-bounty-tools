---
description: Apply a deep Web3 vulnerability module to a target
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow `VULNERABILITY_MODULES.md`.

Bug class / target:

`$ARGUMENTS`

Choose the relevant module:

- reentrancy
- integer/math
- access control
- oracle
- signature
- bridge
- ERC4626
- account abstraction / AI

Return detection patterns, false positives, exploit hypotheses, PoC assertion targets, and canonical statuses.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-vuln-module
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
  target: "<program/repo/contract>"
  summary: "<bug class and top result>"
  bug_class: reentrancy|integer-math|access-control|oracle|signature|bridge|erc4626|account-abstraction-ai|other
  module_leads:
    - id: "<lead id>"
      status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
      source_pointer: "<file:contract:function>"
      false_positive_filter: "<what could refute it>"
      assertion_target: "<profit/loss/freeze/bad debt/privilege/data>"
      evidence_missing: []
      next_action: "<exact command or stop reason>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
