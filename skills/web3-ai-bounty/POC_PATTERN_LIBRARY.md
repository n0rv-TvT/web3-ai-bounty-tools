# Web3 PoC Pattern Library

Purpose: choose a known PoC shape quickly once a lead is marked `PROVE`. Adapt names, actors, balances, and assertions to the actual target. These are patterns, not findings.

## Pattern 1: Accounting Desync / Unearned Rewards

Use when rewards/assets arrive before indexes/snapshots update or when a path skips accounting.

Test name:

```solidity
function test_exploit_attackerClaimsRewardsFundedByPriorStakers() public
```

Shape:

```text
Setup: Alice/victim is sole staker. Reward tokens enter protocol.
Baseline: Alice should receive all rewards if accounting is correct.
Attack: attacker deposits after reward transfer but before update/snapshot, triggers update/claim, withdraws.
Proof: attacker reward gain > 0 and Alice claimable/redeemable reward falls by same amount.
Control: reward update before attacker deposit gives Alice all rewards.
```

Key assertions:

```solidity
assertGt(attackerRewardGain, 0, "attacker received no unearned rewards");
assertEq(attackerRewardGain, aliceRewardLoss, "unearned reward did not come from Alice");
```

## Pattern 2: Exit Before Loss / Bad Debt Shift


Use when loss/debt is reported asynchronously or by permissionless trigger.

Shape:

```text
Setup: attacker and victim both hold shares; strategy has hidden loss.
Baseline: both should share loss pro rata.
Attack: attacker exits before loss report/checkpoint; loss is reported after attacker exits.
Proof: victim absorbs attacker's loss share or protocol becomes undercollateralized.
Control: loss report before attacker exit charges attacker correctly.
```

Key assertions:

```solidity
assertGt(attackerAvoidedLoss, 0, "attacker avoided no loss");
assertLt(victimRedeemableAfter, victimRedeemableBefore - victimFairLoss, "victim did not absorb extra loss");
```

## Pattern 3: ERC4626 First-Depositor Donation Inflation

Use for vaults where share price can be manipulated by direct donations and no virtual shares/assets/min liquidity exist.

Shape:

```text
Setup: empty vault.
Attack: attacker deposits dust, donates assets directly, victim deposits, attacker redeems.
Proof: victim receives zero/fewer shares; attacker redeems victim value.
Control: virtual shares/assets or minimum deposit prevents profit.
```

Key assertions:

```solidity
assertLt(victimShares, expectedFairShares, "victim shares were not diluted");
assertGt(attackerGain, attackerDonationCost, "attack not profitable");
```

Kill if profit is dust or virtual offsets/minimum liquidity eliminate practical impact.

## Pattern 4: Sibling Access-Control Bypass

Use when a batch/alternate/helper path reaches sensitive state without the guard present on the main path.

Shape:

```text
Setup: attacker lacks role required by guarded function.
Baseline: guarded function reverts for attacker.
Attack: attacker calls weaker sibling/helper/batch path.
Proof: restricted state changes or funds move.
Control: authorized role can use intended path.
```

Key assertions:

```solidity
vm.expectRevert();
vm.prank(attacker);
target.guardedAction(...);

vm.prank(attacker);
target.unguardedSibling(...);
assertEq(target.sensitiveState(), attackerChosenValue, "sibling did not bypass guard");
```

## Pattern 5: Signature Replay

Use when nonce/domain/action binding is missing or inconsistently consumed.

Shape:

```text
Setup: victim signs one normal authorization.
Baseline: first use succeeds as expected.
Attack: attacker reuses same signature, or uses it in another function/chain/market.
Proof: state changes twice or in wrong context; attacker gains or victim loses.
Control: consuming nonce / domain-bound signature blocks second use.
```

Key assertions:

```solidity
bytes32 sigHash = keccak256(signature);
// first use
// second use with same signature
assertGt(attackerGain, 0, "replay produced no gain");
assertTrue(usedSignatureTwice[sigHash], "test did not reuse exact signature");
```

## Pattern 6: Packed Encoding Collision

Use when security-critical hashes use `abi.encodePacked` with multiple dynamic fields or ambiguous boundaries.

Shape:

```text
Setup: construct two different semantic payloads with same packed bytes.
Baseline: victim signs benign semantic payload.
Attack: attacker submits malicious semantic payload with same packed hash/signature.
Proof: contract accepts malicious payload; funds/state move.
```

Key assertion:

```solidity
assertEq(keccak256(benignPacked), keccak256(maliciousPacked), "packed payloads do not collide");
assertGt(attackerGain, 0, "collision had no impact");
```

## Pattern 7: Oracle Spot Manipulation / Bad Debt

Use only when an economic path exists.

Shape:

```text
Setup: lending/market uses manipulable spot price.
Baseline: collateral value and max borrow before manipulation.
Attack: attacker manipulates price, borrows/mints/redeems, restores or exits.
Proof: attacker keeps borrowed assets and protocol has bad debt after price normalizes.
Control: TWAP/staleness/confidence check blocks or dampens manipulation.
```

Key assertions:

```solidity
assertGt(attackerProfitAfterRepay, 0, "not profitable after manipulation cost");
assertGt(protocolBadDebt, 0, "protocol has no bad debt");
```

Kill if no realistic liquidity/capital path or only generic manipulation is shown.

## Pattern 8: Reentrancy Double-Claim / Double-Withdraw

Use when external call happens before state update.

Shape:

```text
Setup: attacker contract has position/claim.
Baseline: one withdrawal/claim amount.
Attack: external transfer/callback reenters same or sibling function before state is updated.
Proof: attacker receives more than entitlement.
Control: state update before external call or nonReentrant blocks callback.
```

Key attacker contract shape:

```solidity
contract ReenteringAttacker {
    bool internal entered;

    receive() external payable {
        if (!entered) {
            entered = true;
            // reenter vulnerable function or sibling
        }
    }
}
```

Key assertions:

```solidity
assertGt(attackerReceived, attackerEntitlement, "attacker did not exceed entitlement");
assertLt(address(target).balance, targetBalanceBefore - attackerEntitlement, "target did not lose extra funds");
```

## Pattern 9: Proxy Initialization / Reinitialization Takeover

Use when deployed proxy/implementation remains initializable or reinitializable.

Shape:

```text
Setup: use deployed state or local deployment matching scripts.
Baseline: owner/admin is expected role; attacker lacks role.
Attack: attacker calls initialize/reinitialize/upgrade setup path.
Proof: attacker becomes owner/admin/signer/oracle or changes implementation.
Control: initializer guard or disabled initializers reverts.
```

Key assertions:

```solidity
assertFalse(target.hasRole(ADMIN_ROLE, attacker), "bad baseline");
vm.prank(attacker);
target.initialize(...);
assertTrue(target.hasRole(ADMIN_ROLE, attacker), "attacker did not gain admin");
```

Kill if implementation-only takeover has no impact and is excluded.

## Pattern 10: Bridge Retry/Cancel/Finalize Double Release

Use when message consumed/refunded/finalized state can disagree.

Shape:

```text
Setup: one legitimate bridge lock/burn/message.
Baseline: one message should release/mint exactly once.
Attack: execute finalize/retry/cancel in malicious order or reenter before consumed flag set.
Proof: attacker receives more tokens than locked/burned, or source refund plus destination release occurs.
Control: consumed/refunded flag set before external call and shared across paths.
```

Key assertions:

```solidity
assertEq(messageReleaseCount[id], 2, "message was not executed twice");
assertGt(attackerBridgeGain, amountLocked, "attacker did not receive more than locked");
```

## Pattern 11: Permissionless Trigger Reward/Loss Shift

Use when anyone can call `harvest`, `checkpoint`, `settle`, `sync`, `finalizeEpoch`, or `updateIndex`.

Shape:

```text
Setup: victim cohort has accrued reward/loss not yet checkpointed.
Attack: attacker enters or exits, then calls permissionless trigger at favorable time.
Proof: reward/loss is assigned to wrong cohort.
Control: checkpoint before balance change or user-specific snapshots prevent shift.
```

Key assertions:

```solidity
assertGt(attackerGain, 0, "trigger timing gave no gain");
assertEq(attackerGain, victimCohortLoss, "value shift not proven");
```

## Pattern 12: AI Wallet Unsafe Signing / Tool Call

Use for Web3 AI agents, wallets, or transaction builders.

Shape:

```text
Setup: user asks harmless normal task; attacker controls untrusted text/token metadata/proposal/page.
Baseline: policy requires explicit confirmation for transfer/approval/sign/tool call.
Attack: malicious text causes agent to produce harmful calldata, signature, submission, or backend tool call.
Proof: exact calldata/tool call/secret leak is captured; user did not approve harmful action.
Control: tool policy or confirmation gate blocks action.
```

Evidence targets:

```text
- malicious input payload
- model/tool transcript
- generated transaction target/value/data
- mismatch between UI summary and calldata
- leaked data field or unauthorized backend action
```

Kill prompt injection alone unless it reaches signing, submission, privileged tools, data exposure, or security-sensitive state.

## Pattern 13: Emergency Path Skips Cleanup

Use when emergency withdraw/cancel/rescue skips debt/reward/lock/vote/accounting cleanup.

Shape:

```text
Setup: attacker has position with debt/rewards/locks/votes.
Baseline: normal exit cleans all dependent state.
Attack: attacker uses emergency path to exit assets while dependent state remains.
Proof: attacker claims again, avoids debt, keeps votes, or withdraws locked value.
Control: cleanup before transfer or shared internal exit logic prevents stale state.
```

Key assertions:

```solidity
assertEq(position.assets, 0, "assets not withdrawn");
assertGt(position.claimableRewards, 0, "stale claim not left behind");
assertGt(attackerSecondGain, 0, "stale state was not monetized");
```

## Pattern 14: Fee-On-Transfer / Rebasing Token Desync

Use when protocol supports arbitrary ERC20s or in-scope token has non-standard behavior.

Shape:

```text
Setup: malicious/FOT/rebasing token accepted by protocol.
Baseline: protocol credits amount parameter instead of actual received.
Attack: attacker deposits amount but protocol receives less, then withdraws/borrows based on inflated credit.
Proof: protocol accounting exceeds real balance and attacker extracts value.
Control: use balanceBefore/balanceAfter actual received amount.
```

Key assertions:

```solidity
assertGt(accountedAssets, realTokenBalance, "accounting not inflated");
assertGt(attackerGain, 0, "desync not monetized");
```

Kill if accepted tokens are fixed standard tokens and arbitrary malicious token is out of scope.
