---
description: Design Web3 invariants and fuzz/property tests for a protocol
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Design invariants and a minimal Foundry/Echidna/Medusa harness for:

`$ARGUMENTS`

Return:

1. Protocol state variables that should stay synchronized.
2. Invariants in plain English.
3. Suggested Foundry invariant tests.
4. Suggested Echidna properties when useful.
5. Setup steps for actors, assets, oracle mocks, and handlers.
6. The exact narrow test/fuzz command to run.

Do not write production fixes. Add tests only if the local repository has a suitable test structure or the user explicitly asks.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-invariant
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: LEAD|PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
  target: "<program/repo/contract>"
  summary: "<one sentence>"
  state_variables: []
  invariants:
    - id: "<invariant id>"
      status: LEAD|PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
      description: "<plain English invariant>"
      affected_state: []
      suggested_test: "<Foundry/Echidna/Medusa property>"
      assertion_target: "<what failure proves>"
  harness_setup: []
  execution_command: "<narrow command or null>"
  execution_safety_classification: SAFE_READ_ONLY|SAFE_LOCAL_TEST|SAFE_LOCAL_FORK_READONLY|NEEDS_USER_RPC_CONFIRMATION|NEEDS_USER_NETWORK_CONFIRMATION|REVIEW_REQUIRED|BLOCKED_BROADCAST|BLOCKED_SECRET_REQUIRED|BLOCKED_PRODUCTION_ACTION|BLOCKED_DESTRUCTIVE_COMMAND|BLOCKED_DEPENDENCY_INSTALL|BLOCKED_ENV_ACCESS|NOT_RUN
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
