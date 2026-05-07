---
description: Select a Web3 PoC pattern for a suspected lead
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow `POC_PATTERN_LIBRARY.md`.

Lead:

`$ARGUMENTS`

Return:

1. Closest PoC pattern.
2. Setup / Baseline / Attack / Proof / Control structure.
3. Required adversarial harness, if any.
4. Exact assertions needed to prove impact.
5. Narrow Foundry test command.

Do not write production fixes.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-poc-patterns
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NA_RISK|KILL|AUDIT_NOTE
  target: "<lead>"
  summary: "<one sentence>"
  closest_pattern: "<pattern>"
  setup_steps: []
  baseline_steps: []
  attack_steps: []
  proof_assertions: []
  control_test: "<control test idea>"
  required_harnesses: []
  execution_command: "<narrow command or null>"
  execution_safety_classification: SAFE_READ_ONLY|SAFE_LOCAL_TEST|SAFE_LOCAL_FORK_READONLY|NEEDS_USER_RPC_CONFIRMATION|NEEDS_USER_NETWORK_CONFIRMATION|REVIEW_REQUIRED|BLOCKED_BROADCAST|BLOCKED_SECRET_REQUIRED|BLOCKED_PRODUCTION_ACTION|BLOCKED_DESTRUCTIVE_COMMAND|BLOCKED_DEPENDENCY_INSTALL|BLOCKED_ENV_ACCESS|NOT_RUN
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
