# Web3 Bug Finding Playbook

Purpose: turn contract surface maps into exploit hypotheses and then into passing PoCs. Use this during `/web3-hunt` after scope and high-level surface mapping are complete.

Core rule: every loop must end with one of these outcomes:

- `PROVE`: exact exploit test is clear; write the PoC.
- `CHAIN REQUIRED`: impact is weak alone; needs another bug or condition.
- `KILL`: unreachable, intended behavior, excluded, duplicate, admin-only, scanner-only, or no concrete impact.

## /web3-hunt Operating Loop

1. Identify top 3 crown-jewel components:
   - vault/accounting contract
   - router/market/liquidation contract
   - oracle/signature/bridge/upgrade contract
   - AI wallet/agent signing or tool boundary

2. For each component, answer:
   - Where can funds move?
   - Where can accounting change?
   - Where does user input cross a trust boundary?
   - Which sibling functions do the same job differently?
   - Which invariant would make users whole?

3. Run the relevant loops below.

4. Rank leads:

| Rank | Lead quality | Action |
|---|---|---|
| 1 | Direct theft, bad debt, or unauthorized privileged action with obvious test path | PoC first |
| 2 | Frozen funds with measurable duration and no recovery | PoC if program accepts |
| 3 | Signature replay, oracle/accounting exploit requiring setup | PoC if economic path is realistic |
| 4 | Griefing, dust, admin-trust, generic DoS | Usually KILL |

5. Before coding PoC, write the proof target:

```text
Attacker action:
Expected attacker gain:
Expected victim/protocol loss:
Invariant broken:
Assertion that proves impact:
```

If this cannot be written concretely, mark `KILL` or `CHAIN REQUIRED`.

## Loop 1: Sibling Function Differential

Find functions that should enforce the same checks but do not.

Targets:

- `deposit()` vs `mint()`
- `withdraw()` vs `redeem()`
- `stake()` vs `stakeFor()`
- `claim()` vs `claimFor()` vs `batchClaim()`
- `borrow()` vs `borrowFor()`
- `repay()` vs `repayWithCollateral()`
- `liquidate()` vs `batchLiquidate()`
- `createOrder()` vs `updateOrder()` vs `cancelOrder()`
- `bridgeSend()` vs `retryMessage()` vs `cancelMessage()` vs `finalizeMessage()`
- `execute()` vs `executeBatch()`
- `initialize()` vs `reinitialize()`

Questions:

- Which sibling has extra modifiers, role checks, pause checks, slippage checks, deadline checks, or accounting updates?
- Can the weaker sibling reach the same sensitive state?
- Can attacker use the weaker sibling to bypass a check on the stronger sibling?
- Does a batch path skip per-item validation?

PoC pattern:

```text
Baseline: guarded sibling rejects attacker or preserves invariant.
Attack: weaker sibling succeeds with same economic effect.
Proof: attacker gains, victim/protocol loses, or restricted state changes.
Control: honest guarded path behaves correctly.
```

Kill if the weaker sibling is intentionally permissionless and no harmful state/fund movement occurs.

## Loop 2: Accounting Delta Trace

Use this for vaults, staking, rewards, lending, markets, strategies, and AMMs.

List all functions that change each variable:

```text
totalAssets += / -=
totalSupply += / -=
totalShares += / -=
userShares[user] += / -=
debt[user] += / -=
rewardIndex += / reset
claimable[user] += / -=
```

Then ask:

- Which token transfers happen without accounting updates?
- Which accounting updates happen without token transfers?
- Which emergency/batch/partial path skips an update?
- Can someone enter after assets arrive but before snapshot/accrual?
- Can someone exit before loss/debt/reward is applied?
- Can direct donation, rebasing, fee-on-transfer, strategy loss, or rescue desync balance and accounting?

Exploit hypotheses:

- attacker deposits after reward transfer but before index update and claims unearned rewards
- attacker withdraws before loss is reported, leaving bad debt for remaining users
- attacker donates to manipulate share price then steals first depositor/rounding value
- emergency withdrawal skips debt cleanup and lets attacker borrow/claim again
- batch claim updates global index once but credits users multiple times

PoC assertions:

```solidity
assertGt(attackerGain, 0, "attacker did not profit");
assertEq(protocolAssetsAfter + attackerGain, protocolAssetsBefore, "value moved from protocol to attacker");
assertLt(victimRedeemableAfter, victimRedeemableBefore, "victim redeemable assets did not fall");
```

Kill if no attacker can choose timing/order or if admin-only accounting correction is documented and accepted by the program.

## Loop 3: ERC4626 And Share Inflation

Use for any vault-like share/accounting system, even if not formally ERC4626.

Boundary tests:

- first depositor
- `totalSupply == 0`
- one wei deposit
- direct donation before victim deposit
- last withdrawer
- total assets after loss
- `previewDeposit`, `previewMint`, `previewWithdraw`, `previewRedeem` vs actual execution

Exploit hypotheses:

- attacker seeds tiny shares, donates assets, victim mints zero or too few shares, attacker redeems donation plus victim value
- rounding favors attacker on repeated deposit/withdraw cycles
- share transfers bypass reward/lock/vote checkpoint updates
- vault uses live token balance in one path and cached accounting in another

PoC pattern:

```text
Setup: attacker first depositor with dust.
Baseline: victim deposit amount and expected fair shares.
Attack: attacker donation or share price manipulation before victim deposit.
Proof: victim receives fewer shares/assets; attacker redeems profit.
Control: virtual shares/assets or minimum liquidity prevents profit.
```

Kill if expected loss is dust below program thresholds or protected by minimum deposit/virtual offsets.

## Loop 4: Signature Replay And Domain Confusion

Use for permits, orders, intents, withdrawals, meta-transactions, bridge messages, governance votes, AI transaction approvals.

Checklist:

- nonce consumed exactly once?
- deadline enforced?
- verifying contract included?
- chain ID included?
- function/action/typehash included?
- recipient, token, amount, market, order ID, salt included?
- cancellation and fill share the same nonce state?
- `abi.encodePacked` collision possible?
- signature valid across proxy/implementation or cloned markets?

Exploit hypotheses:

- same signature fills order twice
- withdrawal authorization replays on another chain or market
- signed approval for one action executes another action
- cancelled order remains fillable through batch/alternate path
- AI-signed calldata not bound to exact target/value/data shown to user

PoC pattern:

```text
Setup: signer signs one valid authorization.
Attack: attacker submits same signature twice or in wrong context.
Proof: nonce not consumed or context not bound; funds/state move twice or incorrectly.
```

PoC assertions:

```solidity
assertEq(nonceAfterFirstUse, nonceAfterSecondUse, "nonce was not consumed");
assertGt(attackerGain, 0, "replay produced no gain");
```

Kill if replay requires signer to sign malformed data outside normal UX and no normal victim path exists.

## Loop 5: Oracle And Liquidation Economics

Use for lending, perps, vault share pricing, AMMs, collateral, liquidation, mint/redeem, rebalance.

Checklist:

- stale price rejected?
- negative/zero price rejected?
- confidence interval checked?
- sequencer uptime checked on L2?
- decimals normalized?
- TWAP window adequate?
- fallback oracle cannot be forced into weaker mode?
- spot price not used for high-value action?
- price update and action can happen same block?

Exploit hypotheses:

- manipulate spot/TWAP then borrow over collateral value
- force fallback oracle then mint/redeem at wrong price
- stale price allows undercollateralized borrow or bad liquidation
- decimals mismatch overvalues collateral
- same-block update lets attacker liquidate healthy position

PoC requirements:

- prove capital path or use fork/liquidity state if needed
- prove profit or bad debt after repaying flash loan if flash loan is assumed
- prove victim was healthy before manipulation if claiming bad liquidation

Kill if it only says “oracle can be manipulated” without showing profitable action or accepted impact.

## Loop 6: Reentrancy And Callback State Observation

Use wherever external calls happen before state is finalized.

Callback sources:

- ETH `call`
- ERC777 hooks
- ERC721/1155 receiver hooks
- ERC20 tokens with callbacks or malicious token in scope
- DEX swap callbacks
- flash loan callbacks
- bridge callbacks
- strategy hooks
- arbitrary `delegatecall`/tool calls

Questions:

- What state is stale during the external call?
- Which sibling lacks `nonReentrant`?
- Can read-only reentrancy observe inflated rate/reserves?
- Can attacker withdraw/claim/borrow twice before balance/debt updates?

PoC pattern:

```text
Setup: attacker contract enters protocol.
Attack: callback reenters vulnerable sibling while state is stale.
Proof: double withdrawal/claim/borrow or manipulated read-only rate.
```

Kill if no attacker-controlled callback exists for in-scope assets.

## Loop 7: Proxy, Initialization, And Upgrade Takeover

Use for upgradeable protocols and clones.

Checklist:

- proxy initialized?
- implementation initialized or `_disableInitializers()` called?
- `initialize`/`reinitialize` protected?
- upgrade function authorized?
- storage layout safe across versions?
- clone init calldata cannot be front-run/reused?
- owner/admin after deployment matches expected multisig/timelock?

Exploit hypotheses:

- attacker initializes implementation/proxy and becomes owner
- attacker reinitializes module to change signer/oracle/asset
- attacker upgrades implementation through unguarded path
- storage collision changes owner/accounting after upgrade

PoC proof:

```solidity
assertEq(protocol.owner(), attacker, "attacker did not become owner");
assertTrue(protocol.hasRole(ADMIN_ROLE, attacker), "attacker did not gain admin");
```

Kill if only implementation takeover has no effect and program excludes it.

## Loop 8: Bridge Replay, Retry, Cancel, Finalize

Use for cross-chain escrow, mint/burn, lock/release, message relayers.

Checklist:

- message ID unique across source chain, destination chain, sender, receiver, nonce, payload?
- consumed messages marked before external call?
- retry cannot execute after cancel/refund?
- cancel cannot happen after finalize?
- trusted remotes/domain IDs verified?
- token decimals/representation consistent across chains?
- failure path does not mint/release twice?

Exploit hypotheses:

- replay message mints/releases twice
- cancel refunds source while retry finalizes destination
- malformed domain routes message to wrong receiver
- external callback during finalize reenters before consumed flag set

PoC pattern:

```text
Setup: one legitimate bridge message.
Attack: replay/retry/cancel/finalize in malicious order.
Proof: attacker receives more tokens than locked/burned or victim funds are unrecoverably stuck.
```

Kill if delayed fulfillment/retry queue is explicitly intended and no accepted freeze duration is proven.

## Loop 9: Permissionless Trigger Value Shift

Use for `harvest`, `checkpoint`, `settle`, `rebalance`, `liquidate`, `poke`, `sync`, `updateIndex`, `finalizeEpoch`, `claimFor`.

Questions:

- Who benefits from choosing exact timing?
- Can attacker enter before trigger and exit after?
- Can attacker trigger before victim update/checkpoint?
- Can trigger use stale balances, shares, votes, or prices?
- Can trigger permanently move rewards/losses between cohorts?

Exploit hypotheses:

- attacker deposits, calls permissionless update, captures rewards meant for prior stakers
- attacker triggers loss after withdrawing, pushing loss to remaining users
- attacker finalizes epoch with manipulated state
- attacker calls `sync` after donation to alter share price or collateral value

Kill if effect is only MEV/frontrunning and program excludes it. Reframe only when deterministic state corruption exists without relying on mempool ordering.

## Loop 10: AI Wallet / Agent Harmful Capability Chain

Use for AI-enabled Web3 targets.

Map reads:

- untrusted token/NFT metadata
- websites/docs/proposals
- chat/memory
- portfolio labels/history
- secrets/API keys/session tokens

Map actions:

- sign
- submit transaction
- approve/transfer/swap/bridge
- modify delegates/permissions
- call admin/backend/MCP tools
- persist memory/instructions

Exploit hypotheses:

- indirect prompt injection in token metadata causes agent to create harmful approval/transfer
- malicious proposal text causes agent to vote/sign against user intent
- user-controlled input causes backend/admin tool call
- cross-user memory leaks wallet labels, balances, or private notes
- AI summary says harmless action while calldata approves attacker

PoC requirements:

- show exact untrusted input
- show exact tool call / calldata / signature / leaked data
- show missing confirmation or policy bypass
- prove user did not authorize harmful action beyond normal use

Kill prompt leakage alone unless it exposes secrets or enables a harmful capability.

## Fast Kill Rules

Immediately mark `KILL` when:

- finding is scanner-only and no manual exploit path exists
- only privileged owner/admin can exploit and no privilege bypass exists
- issue is documented as intended or known accepted risk
- affected address/chain/function is out of scope
- impact is only inconvenience, dust, style, gas, missing event, missing comment, centralization, or theoretical risk
- PoC cannot prove attacker gain, victim/protocol loss, bad debt, unauthorized action, accepted freeze duration, or data exposure
- exploit requires stolen keys, compromised oracle, malicious admin, or victim signing abnormal data unless that is the vulnerability being proven

## Best Lead Selection Heuristic

Pick the lead with the strongest combination:

```text
score = direct_impact + normal_attacker + normal_victim + simple_poc + in_scope + not_duplicate - exclusions - admin_dependency
```

Prefer:

1. Direct theft or bad debt with exact balance assertions.
2. Unauthorized privileged action from normal attacker.
3. Signature replay with same signature reused.
4. Accounting desync with victim loss/attacker gain.
5. Oracle exploit with realistic economic path.
6. AI unsafe signing/tool misuse with concrete harmful action.

Avoid spending time on leads that need long speculative chains unless no stronger lead exists.
