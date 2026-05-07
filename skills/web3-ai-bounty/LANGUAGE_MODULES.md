# Language-Specific Web3 Audit Modules

Purpose: extend the hunter beyond Solidity into Vyper and Rust-based smart contracts. Language modules are hunting guides and tool plans; findings still require concrete impact and PoCs.

## Solidity / EVM Module

### Tooling

```bash
forge build
forge test
slither .
aderyn .
semgrep --config=p/security-audit .
myth analyze <contract.sol>
halmos
echidna .
medusa fuzz
wake detect
```

### High-priority constructs

- ERC4626 vaults and share math.
- EIP-712 signatures, ERC-1271, Permit2.
- UUPS/Transparent/Beacon/Diamond proxies.
- LayerZero/OFT and cross-chain messaging.
- Account abstraction, paymasters, session keys, EIP-7702.
- Assembly, low-level calls, delegatecall.

### Common bug classes

- reentrancy: single, cross-function, cross-contract, read-only, callback-based
- math: rounding, decimals, downcasts, overflow, division-before-multiplication
- access control: sibling mismatch, initialization, upgrade auth, confused deputy
- oracle: stale price, spot manipulation, wrong decimals, L2 sequencer
- signature: nonce/deadline/chainId/verifyingContract/action binding
- ERC integration: non-standard ERC20, ERC777 hooks, ERC721/1155 callbacks

## Vyper / EVM Module

### Tooling

```bash
vyper --version
vyper -f abi,bytecode <file.vy>
slither .        # when supported by project layout
ape test         # if Ape project
boa test         # titanoboa projects
semgrep --config=p/security-audit .
```

### Vyper-specific checks

- `@external` vs `@internal` visibility and missing access checks.
- `@nonreentrant` keys: same key protects all related paths?
- `raw_call`: return data length, revert bubbling, gas, value transfer.
- `default_return_value` / `max_outsize` assumptions.
- Decimal math and fixed-size integer bounds.
- `empty(address)` sentinel handling.
- External call before storage update.
- Storage layout in upgradeable Vyper proxies.
- `create_forwarder_to` / blueprint deployment assumptions.
- ERC20 return handling differences.

### Vyper PoC pattern

Prefer Ape/Titanoboa tests or Foundry fork tests calling deployed Vyper bytecode. Assertions are the same: attacker gain, victim/protocol loss, bad debt, unauthorized action.

## Rust: Solana / Anchor Module

### Tooling

```bash
cargo test
cargo clippy -- -D warnings
cargo audit
cargo deny check
cargo geiger
anchor test
trident fuzz
mollusk
litesvm tests
```

### Solana/Anchor bug classes

- missing signer checks
- missing account owner checks
- PDA seed collision or missing bump validation
- account reinitialization / init-if-needed misuse
- unchecked `remaining_accounts`
- CPI privilege confusion / arbitrary CPI target
- token account mint/owner mismatch
- close-account lamport theft or revival
- rent exemption assumptions
- integer precision loss in token decimals
- stale oracle or price account validation missing
- sysvar spoofing / wrong program ID
- duplicate mutable accounts

### PoC targets

- unauthorized account mutation
- token transfer from wrong authority
- PDA takeover or collision
- double spend/claim
- draining lamports through close/reinit

## Rust: CosmWasm Module

### Tooling

```bash
cargo test
cargo clippy
cargo audit
cargo deny check
cargo wasm
cw-multi-test
```

### CosmWasm bug classes

- missing sender/admin validation in execute messages
- reply handler state machine mismatch
- instantiate/migrate authorization bugs
- submessage reply spoofing assumptions
- funds denom/amount validation missing
- decimal precision errors
- storage key collision/version migration bugs
- IBC packet timeout/ack/reply mismatch

## Rust: ink! / Substrate Module

### Tooling

```bash
cargo test
cargo clippy
cargo contract build
cargo audit
```

### ink!/Substrate bug classes

- caller authorization missing
- cross-contract call reentrancy
- storage migration mismatch
- balance transfer failure handling
- arithmetic precision/bounds
- access-control role initialization

## Rust: Arbitrum Stylus Module

### Tooling

```bash
cargo test
cargo stylus check
cargo clippy
cargo audit
```

### Stylus bug classes

- Solidity/Rust ABI mismatch
- EVM storage layout mismatch
- unsafe external calls
- ERC interface noncompliance
- arithmetic/decimal mismatch
- authorization across Solidity/Rust boundary

## Cross-Language Audit Rule

Map language-specific constructs back to the same bounty impact categories:

```text
stolen funds, frozen funds, bad debt, unauthorized privileged action, account takeover, sensitive data exposure, unsafe signing/tool execution
```

No concrete impact means `KILL` or `CHAIN_REQUIRED` regardless of language.
