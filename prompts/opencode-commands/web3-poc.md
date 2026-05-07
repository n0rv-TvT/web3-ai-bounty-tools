---
description: Build one safety-gated Foundry PoC for a specific Web3 finding hypothesis
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Build one minimal PoC for this specific `PROVE` lead:

`$ARGUMENTS`

Do not build multiple PoCs in one pass unless the user explicitly asks.

## Required pre-PoC fields

Before writing tests, confirm:

- exact file/contract/function
- scope artifact or equivalent target brief
- vulnerable code path
- attacker capability
- affected asset
- exploit sequence
- concrete assertion target
- kill condition
- selected severity mode
- duplicate/N/A risk notes

If any field is missing, stop and return `NEEDS_CONTEXT` with the missing fields.

## PoC requirements

1. Inspect relevant contracts, tests, fixtures, deployment scripts, and interfaces before editing.
2. If the finding is in Lead DB or has on-chain/code-index artifacts, generate a scaffold first when useful:
   ```bash
   python3 <skill-dir>/scripts/foundry_poc_generator.py --project-root . --lead-db audit-leads.json --lead-id <lead-id> --onchain onchain.json --code-index x-ray/code-index.json --out test/<LeadId>Exploit.t.sol
   ```
3. Add the smallest useful exploit test.
4. Add a `test_control_*` test where practical.
5. Use named actors such as `attacker`, `victim`, `keeper`, `governor`, or `lp`.
6. Assert concrete impact or invariant break. No assertion means no report-ready finding.
7. Include the kill condition in comments or PoC notes.
8. Run `/web3-exec-gate` or `execution_safety_gate.py` before execution. Do not run direct `forge test` if the project/workflow requires `poc_execution_gate.py`.
9. If the PoC fails because the protocol blocks the exploit, mark `KILL` and explain the blocking source path.

## Safety

- Do not modify production contract code unless explicitly asked to patch.
- Do not use real private keys, seed phrases, user funds, or broadcasts.
- Do not use RPC/fork tests unless explicitly authorized and necessary.
- Prefer local deterministic tests first.

## Output

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-poc
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NA_RISK|KILL
  target: "<program/repo/contract>"
  summary: "<one sentence>"
  finding_id: "<id>"
  source_pointer: "<file:contract:function>"
  scope_artifact: "target-scope.json|audit-notes/target-scope.json|not_written"
  test_file: "<path or null>"
  exploit_test: "<test name or null>"
  control_test: "<test name or null>"
  assertion: "<exact impact assertion or missing>"
  kill_condition: "<what refutes the hypothesis>"
  safety:
    gate_command: "/web3-exec-gate <execution_command> or python3 <skill-dir>/scripts/execution_safety_gate.py --command '<execution_command>'"
    classification: SAFE_READ_ONLY|SAFE_LOCAL_TEST|SAFE_LOCAL_FORK_READONLY|NEEDS_USER_RPC_CONFIRMATION|NEEDS_USER_NETWORK_CONFIRMATION|REVIEW_REQUIRED|BLOCKED_BROADCAST|BLOCKED_SECRET_REQUIRED|BLOCKED_PRODUCTION_ACTION|BLOCKED_DESTRUCTIVE_COMMAND|BLOCKED_DEPENDENCY_INSTALL|BLOCKED_ENV_ACCESS|NOT_RUN
    allowed_to_execute: true|false
    requires_user_confirmation: true|false
  execution_command: "<narrow command or null>"
  poc_result: PASS|FAIL|NOT_RUN
  evidence_missing: []
  last_result: "<short result>"
  next_action: "/web3-validate <finding id/context>"
```

Do not mark Lead DB PoC status as `PASS` until the exploit test passes and asserts concrete impact.
