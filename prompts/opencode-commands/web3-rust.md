---
description: Run Rust-based smart contract audit module
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow the Rust sections of `LANGUAGE_MODULES.md`.

Target:

`$ARGUMENTS`

Classify ecosystem: Solana/Anchor, CosmWasm, ink!, or Arbitrum Stylus.

Focus on signer/owner/account checks, PDA seeds, CPI privilege confusion, account reinitialization, unchecked remaining accounts, token account validation, close-account bugs, reply/state-machine mismatches, storage migrations, and arithmetic precision.

Return tool plan, high-risk constructs, and canonical-status leads.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-rust
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
  target: "<program/repo/contract>"
  summary: "<ecosystem and top risk>"
  ecosystem: solana-anchor|cosmwasm|ink|stylus|unknown
  tool_plan: []
  rust_leads:
    - id: "<lead id>"
      status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
      source_pointer: "<file:module:function>"
      risk_construct: "<signer/PDA/CPI/account/reply/storage/math/etc>"
      impact_claim: "<accepted impact or why weak>"
      evidence_missing: []
      next_action: "<exact command or stop reason>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
