# Attack Vector Triage

Purpose: use known vector libraries as a queue, not as a substitute for reasoning. Inspired by public Solidity audit vector-scan skills and adapted for bounty-grade PoC validation.

Primary local database: `ATTACK_VECTOR_DB.md`.

## Classification States

Every vector must be classified exactly once:

```text
SKIP: construct absent from target
DROP: construct present but guard unambiguously blocks all paths
INVESTIGATE: construct present and guard is missing/partial/unclear
PROVE: full reachable exploit path is visible; write PoC
KILL: investigated but no concrete impact/reachability/scope
```

## Classification Block

For `/web3-vectors`, start with:

```text
SKIP: V2,V5,V9
DROP: V1,V7
INVESTIGATE: V3,V4
PROVE: V6
KILL: V8
Total: 9 classified
```

Then show only `INVESTIGATE`, `PROVE`, and notable `KILL` reasoning.

## Database Use

1. Filter `ATTACK_VECTOR_DB.md` by protocol type and constructs actually present.
2. Select the top 20-40 relevant vectors for medium targets; do not classify irrelevant groups if the construct is absent.
3. For each selected vector, quote the matched construct and guard status.
4. Promote to `PROVE` only when the exploit sentence and PoC assertion are concrete.

## Vector Match Formula

Only investigate if all three exist:

```text
construct present + reachable path + missing/partial guard
```

Promote to `PROVE` only if:

```text
ordered exploit steps + concrete impact + PoC assertion target
```

## Priority Vector Families

### ERC4626 / Vaults

- first depositor inflation
- preview vs execution mismatch
- convertToAssets used where previewWithdraw is required
- maxDeposit/maxWithdraw lies under pause/cap conditions
- round-trip profit extraction
- missing slippage on withdraw/redeem
- direct-donation cached balance desync

### Rewards / Staking

- reward rate changed without accumulator settlement
- notifyReward overwrites active reward period
- same-block deposit-withdraw captures snapshot benefits
- cached reward debt not reset after claim
- reward accrual during zero-depositor period
- emergency exit leaves rewards/votes/locks

### Lending / Perps

- accrued interest omitted from health factor
- no buffer between max LTV and liquidation threshold
- stale/spot/wrong-decimal oracle creates bad debt
- partial liquidation leaves position worse
- repeated liquidation of same position
- position reduction triggers liquidation
- borrower front-runs liquidation if not excluded

### Bridges / Cross-Chain / LayerZero / OFT

- missing endpoint/peer validation
- lzCompose sender impersonation
- missing message uniqueness/chain ID
- retry/cancel/finalize state disagreement
- cross-chain supply accounting violation
- OFT `_debit` authorization missing
- shared-decimals truncation/overflow
- ordered message channel blocking
- missing enforced options / insufficient gas

### Account Abstraction / EIP-7702 / Paymasters

- validateUserOp signature not bound to nonce/chainId
- validateUserOp missing EntryPoint restriction
- paymaster unused gas penalty undercounted
- paymaster ERC20 payment deferred without pre-validation
- EIP-7702 code-inspection invalidation
- EIP-7702 delegated EOA reentrancy/DoS
- EIP-7702 cross-chain authorization replay
- session key / userOp policy bypass through batch/delegatecall

### Tokens / ERC721 / ERC1155

- non-standard ERC20 return values
- zero-first approve / max-approval revert
- fee-on-transfer and rebasing accounting
- ERC721/ERC1155 callback reentrancy
- ERC1155 batch transfer partial-state window
- ERC1155 ID type confusion or role token confusion
- NFT staking records `msg.sender` instead of `ownerOf`

### Proxies / Upgrades / Storage

- uninitialized implementation/proxy
- reinitialization attack
- UUPS authorizeUpgrade missing access control
- transparent proxy admin routing confusion
- diamond facet selector/storage collision
- storage layout shift on upgrade
- arbitrary delegatecall / selector clash

### Signatures / Hashing

- missing nonce
- missing chain ID or verifying contract
- signature malleability
- `ecrecover` returns address(0)
- `abi.encodePacked` collision with dynamic types
- merkle leaf not bound to caller/action/amount/context
- commit-reveal not bound to sender

### Execution / Assembly / Calldata

- dirty higher-order bits
- hardcoded calldataload offset
- calldata input malleability
- free memory pointer/scratch corruption
- assembly delegatecall missing return/revert propagation
- insufficient return-data length validation
- msg.value reuse in loop/multicall

## Guard Break Questions

For every relevant vector:

- Can the same state be reached through a sibling without the guard?
- Can a batch/multicall path bypass per-item validation?
- Is the guard after an external call or after stale read?
- Is one side of a cross-chain/message flow guarded but the other side not?
- Does the guard protect parameters but not storage write sites?
- Does the guard assume token/oracle behavior that can change?

## Output Format For Investigated Vector

```text
Vector V-<id>: <name>
State: INVESTIGATE | PROVE | KILL
Construct present:
Reachable path:
Guard status:
Exploit sentence:
Impact target:
PoC assertion:
Next action:
```

## Kill Discipline

Kill vectors aggressively when:

- the protocol lacks the construct
- all paths are guarded by the same effective check
- exploit requires out-of-scope malicious token/admin/relayer/oracle compromise
- impact is only dust, self-harm, style, or excluded MEV/griefing
- no PoC assertion can be named
