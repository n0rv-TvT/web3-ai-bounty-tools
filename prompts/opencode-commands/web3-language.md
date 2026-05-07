---
description: Select language-specific Web3 audit module and tool plan
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow `LANGUAGE_MODULES.md`.

Target:

`$ARGUMENTS`

Classify language/ecosystem:

- Solidity/EVM
- Vyper/EVM
- Rust/Solana/Anchor
- Rust/CosmWasm
- Rust/ink!
- Rust/Arbitrum Stylus

Return:

1. Tool commands to run.
2. Language-specific high-risk constructs.
3. Bug classes to prioritize.
4. PoC/test framework recommendation.
5. Fast-kill conditions.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-language
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|LEAD|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|KILL|AUDIT_NOTE|LOW_INFO
  target: "<program/repo>"
  summary: "<one sentence>"
  ecosystem: solidity-evm|vyper-evm|solana-anchor|cosmwasm|ink|stylus|unknown
  tool_plan: []
  high_risk_constructs: []
  priority_bug_classes: []
  poc_framework: "<Foundry/Hardhat/Ape/cargo/etc>"
  fast_kill_conditions: []
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
