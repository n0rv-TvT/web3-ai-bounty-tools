---
description: Verify deployed Web3 contract code, source, proxy, and live state using read-only calls
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Follow `ONCHAIN_VERIFICATION.md` and `RPC_CONFIG.md`.

Target address / args:

`$ARGUMENTS`

Use only read-only calls. Never broadcast transactions. Do not hardcode, print, or store RPC URLs or explorer API keys. Classify RPC/network commands with `/web3-exec-gate`; if classified `NEEDS_USER_RPC_CONFIRMATION`, ask before running.

Preferred helper:

```bash
python3 <skill-dir>/scripts/onchain_verify.py <address> \
  --chain-id <id> \
  --rpc-env <CHAIN_RPC_ENV> \
  --json onchain.json
```

If no RPC is available but the chain ID is known, still try source verification:

```bash
python3 <skill-dir>/scripts/onchain_verify.py <address> --chain-id <id> --json onchain-source-only.json
```

When supplied, include in-scope asset token balances:

```bash
python3 <skill-dir>/scripts/onchain_verify.py <address> --chain-id <id> --token <asset-token> --json onchain.json
```

Return:

1. Chain ID, block, code presence, runtime hash.
2. EIP-1967 proxy implementation/admin/beacon slots and effective implementation.
3. Sourcify/explorer verification status for target and implementation.
4. Common calls: owner/admin/paused/totalSupply/totalAssets/name/symbol/decimals when available.
5. Token balances/value-at-risk if token addresses are supplied.
6. Expected deployment check results if expected implementation/name/hash was supplied.
7. What this means for exploit reachability, scope, and whether the lead should stay `LEAD`, become `PROVE`, become `CHAIN_REQUIRED`, or be killed.
8. Execution safety classification for any RPC/helper command.

Attach the JSON as a Lead DB `onchain` artifact when maintaining `audit-leads.json`.

This is validation support, not a finding by itself. A local/fork PoC with assertions is still required.

Return this parseable block first:

```yaml
web3_result:
  schema_version: web3-ai-bounty/v1
  command: web3-onchain
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  status: LEAD|PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|NA_RISK|KILL
  target: "<program/repo/address>"
  summary: "<one sentence>"
  execution_safety_classification: SAFE_READ_ONLY|SAFE_LOCAL_TEST|SAFE_LOCAL_FORK_READONLY|NEEDS_USER_RPC_CONFIRMATION|NEEDS_USER_NETWORK_CONFIRMATION|REVIEW_REQUIRED|BLOCKED_BROADCAST|BLOCKED_SECRET_REQUIRED|BLOCKED_PRODUCTION_ACTION|BLOCKED_DESTRUCTIVE_COMMAND|BLOCKED_DEPENDENCY_INSTALL|BLOCKED_ENV_ACCESS|NOT_RUN
  onchain_artifact: "onchain.json|onchain-source-only.json|not_written"
  chain_id: "<id or unknown>"
  address: "<address or unknown>"
  code_verified: true|false|unknown
  proxy_resolved: true|false|unknown
  value_at_risk: "<amount/notes/unknown>"
  scope_relevance: "<in-scope/out-of-scope/unknown>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```
