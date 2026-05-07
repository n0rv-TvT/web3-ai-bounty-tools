---
description: Generate a Foundry fork/local PoC scaffold from Web3 audit artifacts
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow `FOUNDRY_POC_GENERATOR.md`, `POC_PATTERN_LIBRARY.md`, and `ADVERSARIAL_TEST_HARNESS.md`.

PoC generation request:

`$ARGUMENTS`

Preferred helper:

```bash
python3 <skill-dir>/scripts/foundry_poc_generator.py \
  --project-root . \
  --lead-db audit-leads.json \
  --lead-id <lead-id> \
  --onchain onchain.json \
  --code-index x-ray/code-index.json \
  --out test/<LeadId>Exploit.t.sol \
  --metadata test/<LeadId>Exploit.plan.json
```

If no Lead DB exists, use manual flags:

```bash
python3 <skill-dir>/scripts/foundry_poc_generator.py \
  --project-root . \
  --bug-class <bug-class> \
  --target-address <address> \
  --chain-id <id> \
  --rpc-env <CHAIN_RPC_ENV> \
  --out test/Exploit.t.sol
```

Before recommending any execution command, classify it with `/web3-exec-gate` or `execution_safety_gate.py`.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-foundry-poc
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NA_RISK|KILL
  target: "<program/repo/contract>"
  summary: "<one sentence>"
  generated_solidity_path: "<path or null>"
  metadata_path: "<path or null>"
  selected_poc_pattern: "<pattern>"
  harnesses: []
  execution_command: "<narrow forge command or null>"
  execution_safety_classification: SAFE_READ_ONLY|SAFE_LOCAL_TEST|SAFE_LOCAL_FORK_READONLY|NEEDS_USER_RPC_CONFIRMATION|NEEDS_USER_NETWORK_CONFIRMATION|REVIEW_REQUIRED|BLOCKED_BROADCAST|BLOCKED_SECRET_REQUIRED|BLOCKED_PRODUCTION_ACTION|BLOCKED_DESTRUCTIVE_COMMAND|BLOCKED_DEPENDENCY_INSTALL|BLOCKED_ENV_ACCESS|NOT_RUN
  todos_before_proof: []
  lead_db_command: "<add-poc command>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```

Do not modify production contracts. Do not mark PoC `PASS` from a scaffold alone. Generated exploit tests intentionally fail until completed.
