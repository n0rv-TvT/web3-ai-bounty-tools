# Local Web3 Attack Vector Database

Purpose: local, protocol-grouped vector queue for `/web3-vectors`. Use this as a hypothesis source, not as a finding source. A vector becomes reportable only after source-level reachability, concrete impact, and a passing PoC.

Classification states: `SKIP`, `DROP`, `INVESTIGATE`, `PROVE`, `KILL`.

## Vault / ERC4626 / Yield

| ID | Vector | Construct to match | Prove target | Fast kill |
|---|---|---|---|---|
| V-VAULT-001 | First depositor donation inflation | empty vault + share math uses live balance + no virtual shares | victim mints zero/few shares; attacker redeems profit | virtual offset/min liquidity makes loss dust |
| V-VAULT-002 | Preview/execute mismatch | `preview*` formula differs from `deposit/mint/withdraw/redeem` | UI/integrator gets different shares/assets than preview | mismatch is only fee documented and bounded |
| V-VAULT-003 | `convertToAssets` used where `previewWithdraw` required | withdrawals use optimistic conversion | user withdraws more/less than allowed after fees | code consistently uses preview methods |
| V-VAULT-004 | Missing slippage on withdraw/redeem | vault routes through strategy/AMM without minOut | attacker/victim receives less than accepted category threshold | user supplies minOut elsewhere and it is enforced at final output |
| V-VAULT-005 | Exit before loss report | strategy loss is asynchronous | attacker avoids loss; remaining users absorb it | no attacker-controlled timing or documented trusted loss reporting |
| V-VAULT-006 | Enter before harvest/report | yield/rewards exist before share/index update | late entrant captures prior yield | harvest checkpoints before balance change |
| V-VAULT-007 | Direct donation cached-balance desync | `totalAssets` mixes token balance and cached accounting | donation changes share price/collateral value | direct donation ignored or safely synced |
| V-VAULT-008 | Fee-on-transfer deposit overcredits shares | credits `amount` instead of actual received | accounting exceeds real assets; attacker extracts difference | accepted tokens are fixed standard tokens only |
| V-VAULT-009 | Rebasing underlying desync | token balance changes without protocol accounting | claims exceed real assets or user loss | rebasing token out of scope |
| V-VAULT-010 | Share transfer skips checkpoint | share token transferable + rewards/locks/votes separate | transferred shares keep old boost/reward/vote | transfer hook updates all dependent state |
| V-VAULT-011 | Round-trip profit extraction | deposit->withdraw returns more than input | exact gain after fees/rounding | gain is impossible or dust below threshold |
| V-VAULT-012 | Last withdrawer leaves bad state | totalSupply returns to zero but indexes/caches persist | next depositor inherits stale assets/debt/rewards | state fully reset or virtualized |

## Lending / Borrowing / Liquidation

| ID | Vector | Construct to match | Prove target | Fast kill |
|---|---|---|---|---|
| V-LEND-001 | Stale oracle borrow bad debt | borrow/mint uses stale price | attacker borrows overcollateralized, price normalizes, bad debt remains | freshness and sequencer checks enforced |
| V-LEND-002 | Spot oracle manipulation | AMM reserves/slot0 used for collateral value | profit after manipulation cost/flash loan | TWAP robust for value protected |
| V-LEND-003 | Decimal mismatch collateral overvalue | hardcoded `1e18`, token/feed decimals vary | borrow more than collateral permits | decimals normalized at every path |
| V-LEND-004 | Interest omitted from health factor | health uses principal not accrued debt | withdraw/borrow leaves unsafe account | accrual forced before every health check |
| V-LEND-005 | Borrow index stale on repay/withdraw | lazy interest index | repay too little or withdraw too much | all paths accrue first |
| V-LEND-006 | Partial liquidation rounds wrong | close factor/seize math truncates in liquidator favor | liquidator seizes excess collateral | rounding bounded/dust only |
| V-LEND-007 | Healthy account liquidated | stale/manipulated price or order of checks | victim healthy before call, liquidated after | liquidation checks current normalized price |
| V-LEND-008 | Repeated liquidation same position | state not marked/reduced correctly | same debt/collateral liquidated twice | debt/collateral reduced atomically |
| V-LEND-009 | Self-liquidation profit | borrower can liquidate self or related account | borrower extracts bonus while avoiding debt | self-liquidation blocked or unprofitable |
| V-LEND-010 | Small bad debt unliquidatable | liquidation incentive below gas/min size | bad debt accumulates or withdrawals blocked | protocol has dust sweeping/reserves |
| V-LEND-011 | Repay-with-collateral skips checks | alternate repay path | debt/collateral accounting desync | same internal accounting used by all repay paths |
| V-LEND-012 | Pause blocks liquidations | `whenNotPaused` on liquidation while borrows accrue | bad debt grows during pause | program excludes/admin can safely resolve |

## Staking / Rewards / Gauges

| ID | Vector | Construct to match | Prove target | Fast kill |
|---|---|---|---|---|
| V-REWARD-001 | Reward rate changed without settling accumulator | setter writes rate without `updateReward` | retroactive over/under-payment | modifier settles before setter |
| V-REWARD-002 | `notifyRewardAmount` overwrites active period | new rewards before old period ends | old rewards lost or over-distributed | leftover accounted correctly |
| V-REWARD-003 | Late staker captures prior rewards | reward funded before index update | attacker receives rewards meant for prior stakers | index updated before stake or funding |
| V-REWARD-004 | Reward accrual during zero-depositor period | rewards accrue when `totalStaked == 0` | first later staker claims old rewards | rewards paused/queued with no stakers |
| V-REWARD-005 | Cached reward debt not reset | claim/exit does not update debt | double claim | debt updated before/after consistently |
| V-REWARD-006 | Emergency exit skips cleanup | emergency withdraw leaves claim/vote/lock | exited user monetizes stale state | cleanup shared with normal exit |
| V-REWARD-007 | Same-block snapshot benefit | snapshot uses same-block balance | deposit-vote/claim-withdraw captures benefits | previous-block checkpoint used |
| V-REWARD-008 | Deprecated gauge blocks rewards | gauge removed but rewards remain claimable only through it | accrued rewards stuck beyond accepted duration | migration/claim path exists |
| V-REWARD-009 | Permissionless checkpoint shifts value | anyone can finalize/update index | attacker moves rewards/losses between cohorts | no value shift or MEV excluded |
| V-REWARD-010 | Duplicate array distribution | user-supplied recipients not deduped | recipient paid twice | duplicates rejected or harmless |

## Bridge / Cross-Chain / OFT

| ID | Vector | Construct to match | Prove target | Fast kill |
|---|---|---|---|---|
| V-BRIDGE-001 | Missing endpoint/peer validation | receive/finalize callable without endpoint+peer check | fabricated message mints/releases | inherited verifier clearly checks both |
| V-BRIDGE-002 | Missing message uniqueness | ID omits chain/sender/receiver/nonce/payload | replay in another context | domain separation complete |
| V-BRIDGE-003 | Finalize before consumed flag | external call/token transfer before consumed set | callback finalizes twice | flag set before external call |
| V-BRIDGE-004 | Refund and finalize both succeed | retry/cancel/finalize separate state | source refund + destination release | single state machine blocks conflicts |
| V-BRIDGE-005 | lzCompose sender spoof | compose handler lacks endpoint/origin validation | attacker calls compose directly | endpoint and source app checked |
| V-BRIDGE-006 | OFT debit authorization missing | `_debit`/`_debitFrom` callable/bypassable | unauthorized burn/transfer | authorization bound to owner/spender |
| V-BRIDGE-007 | Shared decimals truncation | OFT amount downcast/truncation | supply/value mismatch | dust refunded/accounted |
| V-BRIDGE-008 | Ordered channel nonce DoS | failed message blocks later messages | accepted frozen funds duration | retry/skip path documented and accepted |
| V-BRIDGE-009 | Missing enforced options/gas | insufficient destination gas | funds stuck/finalization impossible | user can retry with gas safely |
| V-BRIDGE-010 | Cross-chain token identity mismatch | source token != destination token mapping ambiguity | wrong asset released/minted | mapping bound to chain+token+peer |
| V-BRIDGE-011 | Global rate-limit griefing | shared bridge cap consumed by attacker | users frozen beyond accepted duration | per-user/per-path limits or exclusions apply |
| V-BRIDGE-012 | Cross-chain address ownership variance | same address assumed same owner on all chains | unauthorized claim/admin on other chain | proof of ownership bound per chain |

## Signatures / Hashing / Merkle / Intents

| ID | Vector | Construct to match | Prove target | Fast kill |
|---|---|---|---|---|
| V-SIG-001 | Missing nonce | signature accepted without one-time nonce | same signature used twice | nonce consumed before action |
| V-SIG-002 | Missing chainId | signed data reusable across chains | cross-chain replay | EIP-712 domain includes chainId |
| V-SIG-003 | Missing verifyingContract | signed data reusable across clones/markets | replay on another contract | domain binds contract |
| V-SIG-004 | Missing action/type binding | same payload executes different function | unauthorized action | typehash/function included |
| V-SIG-005 | Missing recipient/token/amount binding | signer intent underspecified | redirect or change amount/token | all fields bound |
| V-SIG-006 | `abi.encodePacked` dynamic collision | multiple dynamic fields packed | benign signature validates malicious payload | uses `abi.encode` or delimiters |
| V-SIG-007 | `ecrecover` zero-address acceptance | invalid sig returns address(0) | bypass if signer zero/default | nonzero recovered checked |
| V-SIG-008 | Signature malleability | `s`/`v` not normalized | replay/cancel bypass | OZ ECDSA used |
| V-SIG-009 | Merkle leaf not bound to caller | leaf omits account/context | anyone claims victim allocation | leaf includes account and action |
| V-SIG-010 | Commit-reveal not bound to sender | commitment omits msg.sender/salt domain | reveal stolen/front-run | commitment binds sender |
| V-SIG-011 | Cancel/fill nonce disagreement | order cancel and fill use different state | cancelled order fillable | shared order status |
| V-SIG-012 | Solver intent not bound to min output | off-chain intent allows suboptimal execution | solver extracts value beyond slippage | minOut/deadline bound |

## Proxy / Upgrade / Storage

| ID | Vector | Construct to match | Prove target | Fast kill |
|---|---|---|---|---|
| V-UPG-001 | Uninitialized implementation/proxy | public initializer remains callable | attacker gains owner/admin | initialized or disabled initializers |
| V-UPG-002 | Reinitialization attack | reinitializer reusable or version bug | attacker changes critical config | version lock works |
| V-UPG-003 | UUPS authorizeUpgrade missing | `_authorizeUpgrade` empty/weak | attacker upgrades implementation | only admin/timelock enforced |
| V-UPG-004 | Storage layout collision | proxy/impl or upgrade layout conflict | owner/accounting corrupted | storage layout verified and append-only |
| V-UPG-005 | Transparent proxy admin confusion | admin can hit implementation or user routed wrong | locked function/bypass | proxy pattern correct |
| V-UPG-006 | Selector clash | proxy/facet selector collides | backdoor or wrong function | selector table checked |
| V-UPG-007 | Diamond facet storage collision | facets use shared slots inconsistently | cross-facet corruption | diamond storage namespaced |
| V-UPG-008 | Arbitrary delegatecall | user-supplied target/data delegatecalled | storage takeover/fund theft | target allowlisted and context safe |
| V-UPG-009 | Non-atomic deployment/init | deploy and initialize separate tx | ownership hijack | factory initializes atomically |
| V-UPG-010 | Beacon single point upgrade | beacon controls many vaults | malicious/compromised upgrade drains all | accepted admin risk/excluded |

## AMM / DEX / Router / Hooks

| ID | Vector | Construct to match | Prove target | Fast kill |
|---|---|---|---|---|
| V-AMM-001 | Missing final slippage | slippage checked intermediate, not final | sandwich or bad route output | final recipient amount checked |
| V-AMM-002 | Hardcoded zero slippage | internal swap minOut=0 | extract value through price move | bounded/private route no user funds |
| V-AMM-003 | Spot reserve oracle | reserves/slot0 used for other protocol value | bad debt or unfair liquidation | TWAP/staleness checks |
| V-AMM-004 | Callback settlement reentrancy | swap/mint callback before state finalized | drain/fee bypass | locks and settle checks |
| V-AMM-005 | Fee growth double claim | liquidity/tick update misses checkpoint | LP claims twice | checkpoint before mutation |
| V-AMM-006 | Tick crossing fee manipulation | JIT around deterministic crossing | fee extraction with concrete numbers | expected AMM tradeoff/excluded |
| V-AMM-007 | Empty swap path bypass | router accepts empty/malformed path | token validation bypass | path length checked |
| V-AMM-008 | Recipient confusion | router lets attacker choose recipient for victim flow | output redirected | recipient bound to caller/order |
| V-AMM-009 | Deadline missing/expired not checked | swaps lack deadline | stale transaction execution | program excludes MEV only |
| V-AMM-010 | `msg.value` reuse in multicall | loop/multicall reuses same ETH value | pay once, execute many | msg.value consumed/accounted per call |

## Account Abstraction / Paymaster / EIP-7702 / AI Wallet

| ID | Vector | Construct to match | Prove target | Fast kill |
|---|---|---|---|---|
| V-AA-001 | `validateUserOp` not bound to nonce/chainId | userOp hash incomplete | replay operation | EntryPoint hash used correctly |
| V-AA-002 | Missing EntryPoint restriction | wallet/paymaster validation callable directly | unauthorized execution/state | `msg.sender == entryPoint` enforced |
| V-AA-003 | Paymaster unused gas penalty undercounted | prefund formula omits penalty | paymaster drained | conservative prefund covers penalty |
| V-AA-004 | Paymaster postOp deferred token payment | user can fail payment after sponsorship | paymaster loss | pre-validation locks funds |
| V-AA-005 | Session key target/selector bypass | batch/delegatecall escapes policy | forbidden call executes | policy enforced on decoded subcalls |
| V-AA-006 | EIP-7702 code inspection invalidation | `extcodesize/hash` gates auth/routing | delegated EOA bypass/misroute | no security-critical EXT* branching |
| V-AA-007 | EIP-7702 authorization replay | auth not chain/context bound | replay delegated authority | authorization domain complete |
| V-AA-008 | AI indirect prompt injection to transaction | untrusted text reaches signing/tool call | harmful approval/transfer/signature | explicit confirmation/policy blocks |
| V-AA-009 | AI summary/calldata mismatch | UI summary not decoded from exact calldata | user approves harmful action | exact decoded calldata shown |
| V-AA-010 | Cross-user AI memory leak | shared memory/tool cache | wallet/private data leaked | memory partitioned |

## Tokens / NFTs / Standards

| ID | Vector | Construct to match | Prove target | Fast kill |
|---|---|---|---|---|
| V-TOKEN-001 | Non-standard ERC20 return values | `require(token.transfer(...))` with void-return token | critical path reverts/stuck funds | SafeERC20 used or token fixed standard |
| V-TOKEN-002 | Zero-first approve behavior | USDT-style approvals | critical approval path blocked | forceApprove or allowance reset |
| V-TOKEN-003 | Blacklistable/pausable token path | critical payment asset can block transfer | withdrawals/liquidations frozen | token out of scope or recovery accepted |
| V-TOKEN-004 | Zero-amount transfer revert | protocol assumes zero transfers safe | claim/withdraw loops brick | zero skipped |
| V-TOKEN-005 | ERC777 hook reentrancy | ERC777 accepted in value path | reenter before state update | token out of scope or guard works |
| V-NFT-001 | ERC721 unsafe transfer | uses `transferFrom` to contract | NFT locked/loss | recipient not contract or safeTransfer used |
| V-NFT-002 | ERC721 approval not cleared | custom transfer override | previous approved drains token | approval cleared |
| V-NFT-003 | NFT staking records msg.sender | stake credits caller not owner | delegated/operator steals rewards | ownerOf used and approval checked |
| V-NFT-004 | ERC1155 batch partial callback | supply/accounting updated after callback | reentrant inflation/double claim | state finalized before callback |
| V-NFT-005 | ERC1155 ID role confusion | role encoded as token ID and publicly mintable | unauthorized role | role token mint restricted |
| V-NFT-006 | ERC1155 batch length unchecked | ids/amounts length mismatch in custom loop | accounting mismatch/revert | lengths checked |

## Execution / Assembly / Calldata / External Calls

| ID | Vector | Construct to match | Prove target | Fast kill |
|---|---|---|---|---|
| V-EXEC-001 | Dirty high bits | sub-256-bit calldata/storage used in hashing/auth | auth/hash bypass | values masked/canonical ABI used |
| V-EXEC-002 | Hardcoded calldataload offset | assembly parses calldata manually | non-canonical ABI bypass | decoder validates offsets/lengths |
| V-EXEC-003 | Insufficient return-data validation | low-level call decodes short data | false success/wrong value | length checked |
| V-EXEC-004 | Returndata bomb | unbounded returndata copied | DoS critical path | capped copy/try-catch |
| V-EXEC-005 | Sentinel address operation | address(0)/ETH sentinel treated as ERC20 | revert/no-op/silent success | sentinel handled before token call |
| V-EXEC-006 | Partial state update/early return | coupled vars updated inconsistently | accounting desync | shared internal update or revert atomicity |
| V-EXEC-007 | Stale read reused after external call | snapshot then callback/state change | extract with stale value | read after final state |
| V-EXEC-008 | Push payment DoS | loop sends to arbitrary recipient | one recipient blocks all | pull payments or failure isolation |
| V-EXEC-009 | Duplicate items in array | no dedupe in batch update/distribute | double effect | duplicates rejected/harmless |
| V-EXEC-010 | Memory struct copy not written back | modifies memory copy of storage struct | state update silently missing | storage reference used |

## Governance / Timelock / Delegation

| ID | Vector | Construct to match | Prove target | Fast kill |
|---|---|---|---|---|
| V-GOV-001 | Live supply quorum | quorum uses current supply not snapshot | manipulate supply after vote | snapshot supply used |
| V-GOV-002 | Flash-loan governance | voting power can be borrowed for snapshot/execution | pass malicious proposal | time-weighted/snapshot prevents |
| V-GOV-003 | Same-block vote-transfer-vote | checkpoint allows repeated voting | vote counted twice | per-proposal voted flag |
| V-GOV-004 | Self-delegation doubles power | delegation math double-counts | inflated votes | delegation invariant holds |
| V-GOV-005 | Execute before voting ends | timelock/proposal state bug | proposal executes early | state machine blocks |
| V-GOV-006 | Cancelled proposal executes | cancel/execute states disagree | unauthorized operation | shared proposal state |
| V-GOV-007 | Timelock anchored to deployment | delay not per action | action executes too soon | eta set per queued operation |
| V-GOV-008 | Proposal calldata mutable | target/value/data can change post-vote | voters approve one action, execute another | proposal hash immutable |

## How To Use This DB

1. Filter by protocol type and actual constructs present.
2. For each remaining vector, find the exact entry point and guard.
3. If the guard blocks all paths, `DROP`.
4. If missing/partial, write an exploit sentence and assertion target.
5. Only mark `PROVE` when the PoC path is concrete.
