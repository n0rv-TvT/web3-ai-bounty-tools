---
description: Choose or draft adversarial Web3 test harnesses
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow `ADVERSARIAL_TEST_HARNESS.md`.

Lead or target behavior:

`$ARGUMENTS`

Choose or draft the smallest local test harness needed to prove/kill the lead:

- Fee-on-transfer token.
- Rebasing token.
- No-return / false-return token.
- Reentrant receiver/token/strategy.
- Mutable oracle.
- Malicious bridge receiver.
- Signature replay helper.
- AI tool transcript recorder.

Only add harnesses under test/mock/script paths. Do not modify production contracts unless explicitly asked.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-harness
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NA_RISK|KILL|AUDIT_NOTE
  target: "<lead/repo/contract>"
  summary: "<one sentence>"
  selected_harnesses: []
  harness_paths: []
  production_source_modified: false
  assertion_targets: []
  execution_safety_classification: SAFE_READ_ONLY|SAFE_LOCAL_TEST|SAFE_LOCAL_FORK_READONLY|NEEDS_USER_RPC_CONFIRMATION|NEEDS_USER_NETWORK_CONFIRMATION|REVIEW_REQUIRED|BLOCKED_BROADCAST|BLOCKED_SECRET_REQUIRED|BLOCKED_PRODUCTION_ACTION|BLOCKED_DESTRUCTIVE_COMMAND|BLOCKED_DEPENDENCY_INSTALL|BLOCKED_ENV_ACCESS|NOT_RUN
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
