# RPC Configuration For Web3 Bounty Work

Purpose: enable read-only deployed-state verification and fork PoCs without hardcoding secrets.

## Rules

- Never commit RPC keys or `.env` files with secrets.
- Prefer read-only RPC calls and local fork simulation.
- Never broadcast transactions unless the user explicitly authorizes it.
- Use separate env vars per chain when possible.

## Recommended Environment Variables

```bash
export RPC_URL="https://..."                  # default chain for current target
export MAINNET_RPC_URL="https://..."
export ARBITRUM_RPC_URL="https://..."
export OPTIMISM_RPC_URL="https://..."
export BASE_RPC_URL="https://..."
export POLYGON_RPC_URL="https://..."
export BSC_RPC_URL="https://..."
export AVAX_RPC_URL="https://..."
export BLAST_RPC_URL="https://..."
export LINEA_RPC_URL="https://..."
export SCROLL_RPC_URL="https://..."
export SEPOLIA_RPC_URL="https://..."
```

## Foundry Fork Pattern

```solidity
uint256 fork = vm.createFork(vm.envString("MAINNET_RPC_URL"), 20_000_000);
vm.selectFork(fork);
```

## Cast Read-Only Examples

```bash
cast code <address> --rpc-url "$RPC_URL"
cast storage <address> <slot> --rpc-url "$RPC_URL"
cast call <address> "owner()(address)" --rpc-url "$RPC_URL"
cast call <token> "balanceOf(address)(uint256)" <holder> --rpc-url "$RPC_URL"
```

## On-Chain Verifier Pattern

Prefer the verifier for audit artifacts because it does not store RPC URLs/API keys and it combines RPC, proxy slots, balances, Sourcify, and explorer verification:

```bash
python3 <skill-dir>/scripts/onchain_verify.py <address> --chain-id 1 --rpc-env MAINNET_RPC_URL --json onchain.json
```

For source-only verification when no RPC is available:

```bash
python3 <skill-dir>/scripts/onchain_verify.py <address> --chain-id 1 --json onchain-source-only.json
```

## EIP-1967 Slots

```text
implementation = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
admin          = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
beacon         = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50
```

## On-Chain Verification Goal

For bounty findings, connect source to deployed reality:

```text
source lead -> in-scope deployed address -> proxy implementation -> owner/roles -> live balances/TVL -> oracle state -> fork PoC
```

If the vulnerable code is not deployed, not in scope, or not reachable in live state, mark the lead `KILL` or `CHAIN_REQUIRED`.
