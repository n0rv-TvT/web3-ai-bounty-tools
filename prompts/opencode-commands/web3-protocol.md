---
description: Apply protocol-specific Web3 hunting playbook
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow `PROTOCOL_PLAYBOOKS.md`.

Target:

`$ARGUMENTS`

Classify the target as one or more protocol types: lending, vault, AMM, perps, bridge, staking, liquid staking, governance, account abstraction, or AI wallet.

Return:

1. Asset lifecycle.
2. Crown jewels.
3. Core invariants.
4. High-signal exploit questions.
5. Best PoC targets.
6. Top leads marked with canonical statuses: `PROVE`, `CHAIN_REQUIRED`, `NEEDS_CONTEXT`, `NEEDS_SCOPE_CONFIRMATION`, `NA_RISK`, or `KILL`.

If the target is an AMM, stable swap, concentrated-liquidity pool, or Uniswap v4 hook, also apply `AMM_STABLESWAP_HOOK_CHECKLIST.md`.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-protocol
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
  target: "<program/repo/contract>"
  summary: "<protocol type and crown jewels>"
  protocol_types: []
  checklist_modules: []
  top_leads:
    - id: "<lead id>"
      status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
      source_pointer: "<file:contract:function>"
      impact_claim: "<accepted impact or why weak>"
      evidence_missing: []
      next_action: "<exact command or stop reason>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
