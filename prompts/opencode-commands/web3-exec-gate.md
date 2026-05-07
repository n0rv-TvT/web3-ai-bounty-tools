---
description: Classify Web3 command or PoC execution safety before running it
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow `EXECUTION_SAFETY_GATE.md`.

Command or operation:

`$ARGUMENTS`

## Purpose

Classify whether a proposed command or operation is safe to run. Do not execute the operation in this command unless the classification is `SAFE_READ_ONLY` or `SAFE_LOCAL_TEST` and the user asked you to execute it.

Prefer the helper when available:

```bash
python3 <skill-dir>/scripts/execution_safety_gate.py --command "<command>"
```

## Output

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-exec-gate
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|NEEDS_CONTEXT|NA_RISK|KILL
  target: "<program/repo/contract>"
  summary: "<one sentence>"
  evidence_missing: []
  next_action: "<execute, ask user, or stop>"
execution_safety:
  schema_version: web3-execution-safety/v1
  operation: "<command or file access>"
  operation_type: command|file_read|file_write|network|rpc|poc_execution|unknown
  classification: SAFE_READ_ONLY|SAFE_LOCAL_TEST|SAFE_LOCAL_FORK_READONLY|NEEDS_USER_RPC_CONFIRMATION|NEEDS_USER_NETWORK_CONFIRMATION|REVIEW_REQUIRED|BLOCKED_BROADCAST|BLOCKED_SECRET_REQUIRED|BLOCKED_PRODUCTION_ACTION|BLOCKED_DESTRUCTIVE_COMMAND|BLOCKED_DEPENDENCY_INSTALL|BLOCKED_ENV_ACCESS
  allowed_to_execute: true|false
  requires_user_confirmation: true|false
  reasons: []
  blocked_capabilities: []
  safe_alternative: "<safer command or null>"
  next_action: "<execute, ask user, or stop>"
```

Stop immediately for any `BLOCKED_*` classification. Ask before `NEEDS_*` or `REVIEW_REQUIRED`.
