# Real Paid-Bug Shape Casebook

Purpose: teach the hunter the shape of paid Web3 bugs and the weak variants that usually get rejected. These are generalized patterns, not claims about any specific program.

Use this file with `/web3-casebook` to compare a lead against accepted bug shapes before spending PoC time.

## Paid Shape 1: Late Entrant Captures Prior Rewards

### Root cause

Rewards are funded before reward index/user snapshots update. A new staker can enter before accounting accrues rewards to existing stakers.

### Minimal vulnerable pattern

```text
notifyReward() transfers reward tokens
rewardPerShare updates lazily later
deposit() before update gives new user shares in old reward pool
```

### Exploit steps

1. Victim cohort stakes.
2. Reward tokens arrive.
3. Attacker stakes before reward index update.
4. Attacker triggers update/claim.
5. Attacker withdraws.

### Accepted impact proof

- attacker receives rewards funded for prior stakers
- victim claimable rewards decrease by same amount

### Weak variants rejected

- only changes reward timing with no value loss
- requires admin to fund rewards incorrectly contrary to docs
- attacker profit is dust below severity threshold

## Paid Shape 2: ERC4626 First-Depositor Donation Inflation

### Root cause

Empty vault share price can be manipulated by tiny initial deposit and direct donation because no virtual assets/shares or minimum liquidity exist.

### Exploit steps

1. Attacker deposits dust into empty vault.
2. Attacker donates assets directly.
3. Victim deposits and receives zero/few shares.
4. Attacker redeems inflated shares.

### Accepted impact proof

- victim receives fewer shares than fair value
- attacker exits with more than initial deposit plus donation cost

### Weak variants rejected

- OpenZeppelin virtual offset makes attack unprofitable
- loss is only one wei/dust
- vault has trusted first deposit/minimum liquidity process documented

## Paid Shape 3: Exit Before Loss Report

### Root cause

Strategy loss exists economically but is applied lazily. Users can withdraw at stale share price before loss is reported.

### Exploit steps

1. Attacker and victim hold vault shares.
2. Strategy has loss not yet reflected in vault accounting.
3. Attacker withdraws before loss report.
4. Loss is reported.
5. Remaining users absorb extra loss or protocol has bad debt.

### Accepted impact proof

- attacker avoids loss that should be pro rata
- victim/protocol absorbs attacker's avoided loss

### Weak variants rejected

- loss report timing is privileged/trusted and program excludes oracle/operator trust
- no user-controllable timing
- admin recovery is documented and accepted

## Paid Shape 4: Signature Replay Across Contexts

### Root cause

Signed payload omits nonce, deadline, chain ID, verifying contract, action type, market, token, amount, or recipient.

### Exploit steps

1. Victim signs one normal authorization.
2. Attacker submits signature once.
3. Attacker submits same signature again or on another market/function/chain.
4. Contract accepts second/wrong-context use.

### Accepted impact proof

- same exact signature bytes are reused
- funds/state move twice or outside signed intent

### Weak variants rejected

- victim must sign obviously malicious arbitrary data
- second signature is freshly generated
- replay only works on out-of-scope chain/contract

## Paid Shape 5: Bridge Finalize And Refund Both Succeed

### Root cause

Bridge retry/cancel/finalize paths do not share one message state machine, or consumed/refunded flags are set after external calls.

### Exploit steps

1. Send one bridge message.
2. Trigger failure/refund path on source.
3. Retry or reenter finalize on destination.
4. Receive both refund and destination release/mint.

### Accepted impact proof

- released/minted amount exceeds locked/burned amount
- same message has conflicting finalized/refunded state

### Weak variants rejected

- delayed fulfillment only, documented as intended
- no double release or accepted freeze duration
- requires compromised relayer if relayer trust is excluded

## Paid Shape 6: Oracle Decimal/Staleness Creates Bad Debt

### Root cause

Protocol accepts stale, zero/negative, wrong-decimal, or spot-manipulated price for borrow/mint/liquidation.

### Exploit steps

1. Attacker manipulates or selects bad oracle state.
2. Protocol overvalues collateral or undervalues debt.
3. Attacker borrows/withdraws/mints against bad value.
4. Price normalizes.
5. Protocol has bad debt or victim was unfairly liquidated.

### Accepted impact proof

- attacker profit after manipulation/flash-loan cost
- protocol bad debt or healthy victim liquidation

### Weak variants rejected

- only says spot oracle is manipulable without economic path
- requires unrealistic liquidity/capital not modeled
- no accepted impact after price normalizes

## Paid Shape 7: Sibling Function Missing Guard

### Root cause

Main function has role/slippage/deadline/pause/accounting check, but alternate/batch/helper reaches same state without the check.

### Exploit steps

1. Show guarded function rejects attacker or preserves invariant.
2. Call unguarded sibling with equivalent effect.
3. Restricted state changes or funds move.

### Accepted impact proof

- normal attacker performs action reserved for role/router/vault/owner
- concrete fund movement, bad debt, or security-sensitive state change

### Weak variants rejected

- missing guard only affects harmless config/view/helper
- caller is still constrained by another equivalent check
- centralization/admin-trust only

## Paid Shape 8: Emergency Exit Leaves Monetizable State

### Root cause

Emergency path transfers assets but skips debt, reward, lock, vote, nonce, or position cleanup.

### Exploit steps

1. Attacker creates position with dependent state.
2. Attacker exits through emergency path.
3. Stale dependent state remains.
4. Attacker monetizes stale state: claims rewards again, keeps votes, avoids debt, withdraws locked value.

### Accepted impact proof

- emergency-exited user still gains from stale state
- protocol/victims lose corresponding value or governance state is corrupted

### Weak variants rejected

- stale state is not monetizable
- admin-only emergency action excluded
- only missing event/accounting display issue

## Paid Shape 9: Reentrancy Through Callback Before State Update

### Root cause

External call happens before balance/debt/claim/message state is finalized; sibling lacks reentrancy guard.

### Exploit steps

1. Attacker contract has position or receiver role.
2. Vulnerable function transfers/calls attacker.
3. Callback reenters same/sibling path.
4. Attacker withdraws/claims/finalizes twice or observes stale rate.

### Accepted impact proof

- attacker receives more than entitlement
- target balance/accounting decreases by extra amount

### Weak variants rejected

- callback source is impossible for in-scope assets
- reentry reverts or cannot change outcome
- only theoretical CEI violation with no effect

## Paid Shape 10: AI Wallet Unsafe Signing Boundary

### Root cause

Untrusted content reaches model/tool decision and can influence transaction/signature/tool call without explicit user confirmation or policy enforcement.

### Exploit steps

1. User performs normal AI wallet/task flow.
2. Agent reads attacker-controlled token metadata/webpage/proposal/chat content.
3. Injection changes target/recipient/amount/calldata or tool choice.
4. Agent signs/submits/builds harmful transaction or leaks sensitive data.

### Accepted impact proof

- exact malicious input
- exact generated transaction/tool call/signature/leaked data
- user did not explicitly authorize harmful action
- harmful capability boundary crossed

### Weak variants rejected

- prompt injection only changes text response
- system prompt leakage without secrets or exploit chain
- no signing/submission/tool/data capability reached

## Casebook Rule

If a lead does not resemble one of these paid shapes or another direct accepted-impact shape, be skeptical. Either strengthen it with a concrete chain or kill it.
