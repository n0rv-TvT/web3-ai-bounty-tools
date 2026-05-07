# On-Chain Verification Engine

Production component 4 of the Web3 audit engine.

## Purpose

The On-Chain Verification Engine connects source-level leads to deployed reality. It verifies that the affected code is live, in scope, source-verified where possible, proxy-resolved, and backed by current state/value-at-risk before report drafting.

It is read-only validation support. It never broadcasts transactions and never stores RPC URLs or explorer API keys in artifacts. A local or fork PoC with assertions is still required before any report.

## Files

- CLI: `scripts/onchain_verify.py`
- Legacy first-pass helper: `scripts/onchain_probe.py`
- JSON Schema: `schemas/onchain_verification.schema.json`
- Example output: `examples/onchain_verification.missing_rpc.example.json`
- Default artifact path: `onchain/<chain-id>-<address>.json` or `x-ray/onchain-<address>.json`
- Lead DB artifact type: `onchain`

## What It Verifies

### RPC State

- chain ID and latest block number
- target bytecode presence and runtime SHA-256
- native balance
- EIP-1967 implementation/admin/beacon slots
- beacon implementation if applicable
- EIP-1167 minimal proxy implementation if applicable
- effective implementation bytecode presence and runtime SHA-256
- common calls where available:
  - `owner()`
  - `admin()`
  - `paused()`
  - `totalSupply()`
  - `totalAssets()`
  - `name()` / `symbol()` / `decimals()`
- ERC20 balances for supplied in-scope asset addresses

### Source Verification

- Sourcify full match
- Sourcify partial match
- Etherscan V2 API where `ETHERSCAN_API_KEY` / `EXPLORER_API_KEY` is available
- Blockscout/Etherscan-compatible custom explorer URL
- source verification for both target proxy and effective implementation
- contract name, compiler version, optimizer, EVM version, source file count, ABI availability, proxy flag, explorer implementation field

### Expected-Deployed Checks

Optional checks:

- expected target runtime SHA-256
- expected effective implementation address
- expected verified contract name

These become machine-readable pass/fail rows under `comparisons.checks`.

## Commands

Read-only verification using env RPC:

```bash
python3 <skill-dir>/scripts/onchain_verify.py <address> \
  --chain-id 1 \
  --rpc-env MAINNET_RPC_URL \
  --json onchain/1-<address>.json
```

Use default RPC fallback (`RPC_URL`, chain-specific env vars, then `MAINNET_RPC_URL`):

```bash
python3 <skill-dir>/scripts/onchain_verify.py <address> --chain-id 1 --json onchain.json
```

Probe token value-at-risk:

```bash
python3 <skill-dir>/scripts/onchain_verify.py <address> \
  --chain-id 1 \
  --token <asset-token-address> \
  --json onchain.json
```

Use Sourcify/explorer source verification without RPC, if chain ID is known:

```bash
python3 <skill-dir>/scripts/onchain_verify.py <address> \
  --chain-id 1 \
  --json onchain-source-only.json
```

Use Etherscan V2:

```bash
export ETHERSCAN_API_KEY="<key>"
python3 <skill-dir>/scripts/onchain_verify.py <address> \
  --chain-id 1 \
  --explorer-kind etherscan-v2 \
  --json onchain.json
```

Use a Blockscout/Etherscan-compatible endpoint:

```bash
python3 <skill-dir>/scripts/onchain_verify.py <address> \
  --chain-id 8453 \
  --explorer-url "https://base.blockscout.com/api" \
  --explorer-kind blockscout \
  --json onchain.json
```

Check expected deployment facts:

```bash
python3 <skill-dir>/scripts/onchain_verify.py <proxy> \
  --chain-id 1 \
  --expected-implementation <implementation> \
  --expected-contract-name VaultImplementation \
  --json onchain.json
```

Validate the report schema:

```bash
python3 - <<'PY'
import json, jsonschema
schema=json.load(open('<skill-dir>/schemas/onchain_verification.schema.json'))
data=json.load(open('onchain.json'))
jsonschema.Draft202012Validator(schema).validate(data)
print('on-chain verification schema passed')
PY
```

Attach to Lead DB:

```bash
python3 <skill-dir>/scripts/lead_db.py add-artifact audit-leads.json \
  --type onchain \
  --path onchain.json \
  --tool onchain_verify.py \
  --command "python3 <skill-dir>/scripts/onchain_verify.py <address> --chain-id <id> --json onchain.json" \
  --summary "deployed code/proxy/source/value verification for target"
```

## Environment Variables

RPC URL priority:

1. `--rpc-url` argument
2. `--rpc-env <NAME>`
3. chain-specific env var from `RPC_CONFIG.md`, for example `MAINNET_RPC_URL`, `BASE_RPC_URL`, `ARBITRUM_RPC_URL`
4. `RPC_URL`
5. `MAINNET_RPC_URL`

Explorer API key priority:

1. `--explorer-api-key`
2. `--explorer-api-key-env <NAME>`
3. `ETHERSCAN_API_KEY`
4. `EXPLORER_API_KEY`

The output records only the source of the value, never the secret value itself.

## Verification Checklist

Before report drafting, answer:

1. Is the exact target address in scope?
2. Does the target have runtime bytecode at the chosen block?
3. If it is a proxy, what is the effective implementation?
4. Is the implementation source verified by Sourcify/explorer?
5. Does the verified contract name/compiler match the audited target?
6. Does bytecode/runtime hash match expected deployment artifacts when available?
7. Are owner/admin/guardian/pauser/recovery paths relevant to exploitability or exclusions?
8. Is there live value-at-risk or accepted impact state?
9. Can a fork PoC run against this chain/block and assert the concrete impact?

## Report-Readiness Rule

On-chain verification can satisfy only part of the validation gate:

```text
deployed vulnerable code + in-scope address + reachable current state + value-at-risk evidence
```

It does not prove exploitation. Do not report until a local or fork PoC demonstrates the impact with assertions.

## Kill / Downgrade Signals

Mark the lead `KILL` or `CHAIN_REQUIRED` when:

- target has no runtime bytecode
- affected implementation is not the current proxy implementation
- source is unverified and you cannot prove the deployed bytecode matches the audited code
- address/chain is out of scope
- owner/admin recovery is documented and makes the issue excluded under program rules
- value-at-risk is zero and the accepted impact requires current funds/debt/state
- exploit requires a privileged role unless the bug is privilege bypass

## Safety Rules

- Never store RPC URLs, explorer API keys, private keys, seed phrases, cookies, or bearer tokens.
- Never broadcast transactions.
- Use read-only RPC, source verification APIs, and fork tests.
- Treat explorer/Sourcify data as validation evidence, not a finding by itself.
