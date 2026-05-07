---
description: Run a Web3 baseline scan and summarize high-signal leads
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Use the `web3_audit` MCP if available.

Target: `$ARGUMENTS`

If no target is supplied, use the current repository.

Run this workflow:

1. Call Web3 tool status.
2. Fingerprint the project.
3. Build the contract surface map.
4. Run pattern scans for `accounting`, `access-control`, `oracle`, `erc4626`, `reentrancy`, `signature`, `proxy`, and `ai-agent` as applicable.
5. Before running baseline tools, classify each command with `/web3-exec-gate`; run only commands classified `SAFE_READ_ONLY` or `SAFE_LOCAL_TEST` unless the user explicitly approves.
6. Summarize only high-signal leads with file/function references.
7. For each lead, state the missing proof needed before report writing.

Return this parseable block first. Do not report scanner output as a finding. Convert promising leads into `/web3-poc` work.

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-scan
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: LEAD|PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
  target: "<program/repo/contract>"
  summary: "<one sentence>"
  command_safety: []
  high_signal_leads:
    - id: "<lead id>"
      status: LEAD|PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
      source_pointer: "<file:contract:function>"
      scanner_or_pattern: "<tool/pattern>"
      impact_claim: "<accepted impact or why weak>"
      proof_needed: "<manual trace/PoC assertion>"
      evidence_missing: []
      next_action: "<exact command or stop reason>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
