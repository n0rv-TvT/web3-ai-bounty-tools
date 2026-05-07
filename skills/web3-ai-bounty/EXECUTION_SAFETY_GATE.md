# Execution Safety Gate

Use this before running any command that executes target code, touches network/RPC, writes files, installs dependencies, reads secrets, or could broadcast transactions.

Default rule: local source reading is safe; everything else must be classified. Never broadcast transactions, print secrets, install dependencies, or run destructive commands unless the user explicitly authorizes the exact action and the command is still safe for the target context.

## Canonical Safety Classifications

- `SAFE_READ_ONLY`: reads local non-secret source/docs or lists metadata.
- `SAFE_LOCAL_TEST`: executes local deterministic tests without network, secrets, broadcasts, or production source modification.
- `SAFE_LOCAL_FORK_READONLY`: fork/read-only simulation using user-approved RPC env var; no broadcasts or secret access.
- `NEEDS_USER_RPC_CONFIRMATION`: requires RPC, explorer API, `cast call`, `cast storage`, fork URL, or network fetch.
- `NEEDS_USER_NETWORK_CONFIRMATION`: requires network but not RPC/broadcast, such as public docs fetch or package metadata.
- `REVIEW_REQUIRED`: modifies local non-production files, runs non-allowlisted tools, or cannot be safely classified.
- `BLOCKED_BROADCAST`: broadcasts or can mutate chain state (`cast send`, `--broadcast`, live tx submission).
- `BLOCKED_SECRET_REQUIRED`: reads or requires private keys, seed phrases, cookies, bearer tokens, `.env`, wallet files, or signing material.
- `BLOCKED_PRODUCTION_ACTION`: modifies production contract/source, deployment scripts for live use, or user funds.
- `BLOCKED_DESTRUCTIVE_COMMAND`: destructive local command such as recursive delete, hard reset, force push, or privilege escalation.
- `BLOCKED_DEPENDENCY_INSTALL`: installs or upgrades dependencies without explicit approval.
- `BLOCKED_ENV_ACCESS`: prints environment variables or reads secret-bearing env values directly.

## Allow Rules

`allowed_to_execute` is true only for:

- `SAFE_READ_ONLY`
- `SAFE_LOCAL_TEST`

`SAFE_LOCAL_FORK_READONLY` requires explicit user RPC confirmation unless already provided in scope/testing permissions.

All `BLOCKED_*` classifications must stop. `NEEDS_*` and `REVIEW_REQUIRED` require user confirmation or a safer alternative.

## Required Output

```yaml
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

Validate saved JSON with:

```bash
python3 <skill-dir>/scripts/schema_validator.py execution_safety execution-safety.json
```

Use the helper when available:

```bash
python3 <skill-dir>/scripts/execution_safety_gate.py --command "forge test --match-test test_exploit -vvvv"
```
