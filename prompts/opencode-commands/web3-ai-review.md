---
description: Threat model a Web3 AI agent, wallet, bot, or transaction assistant
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Threat model the Web3 AI system described here:

`$ARGUMENTS`

Map:

1. What the AI can read.
2. What tools the AI can call.
3. Whether it can sign, simulate, submit, approve, swap, bridge, cancel, or change settings.
4. What untrusted content reaches the model.
5. Where user confirmation is enforced.
6. Where secrets, wallet metadata, API keys, prompts, or cross-user context may leak.

Return concrete test cases only. Prioritize chains that prove unauthorized transaction/tool execution, sensitive data exposure, account takeover, or fund loss.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-ai-review
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: LEAD|PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
  target: "<AI wallet/agent/system>"
  summary: "<one sentence>"
  ai_boundaries:
    can_read: []
    can_call_tools: []
    can_sign: true|false|unknown
    can_submit_transactions: true|false|unknown
    reads_untrusted_content: true|false|unknown
    stores_cross_user_context: true|false|unknown
    handles_secrets: true|false|unknown
  test_cases:
    - id: "<test id>"
      status: LEAD|PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
      harmful_capability: "<signing/tool/data/settings/etc>"
      untrusted_input_path: "<path>"
      expected_impact: "<accepted impact>"
      proof_needed: "<test/assertion>"
      next_action: "<exact command or stop reason>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
