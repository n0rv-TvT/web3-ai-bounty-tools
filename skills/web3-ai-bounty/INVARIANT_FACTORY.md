# Web3 Invariant Factory

Purpose: quickly create protocol-specific invariants that expose exploit sequences. Use before or alongside PoCs for stateful bugs.

Invariant tests are lead generators. A broken invariant still needs a concrete impact PoC unless the invariant test itself proves accepted impact.

## Invariant Workflow

1. Pick the protocol type.
2. Choose 2-4 invariants that protect funds or permissions.
3. Write a handler that models normal attacker-accessible actions only.
4. Exclude privileged/admin actions unless privilege bypass is being tested.
5. Add ghost variables for expected value conservation.
6. Run fuzz/invariant tool.
7. Minimize failing sequence into a human PoC.

## Foundry Skeleton

```solidity
contract Handler is Test {
    address[] public actors;

    function deposit(uint256 actorSeed, uint256 amount) external {
        address actor = actors[actorSeed % actors.length];
        amount = bound(amount, 1, 1_000_000e18);
        vm.startPrank(actor);
        // approve + deposit
        vm.stopPrank();
    }

    function withdraw(uint256 actorSeed, uint256 amount) external {
        address actor = actors[actorSeed % actors.length];
        vm.startPrank(actor);
        // withdraw bounded by actor balance
        vm.stopPrank();
    }
}

contract InvariantTest is Test {
    Handler internal handler;

    function setUp() public {
        handler = new Handler();
        targetContract(address(handler));
    }

    function invariant_valueConservation() public {
        // assert core invariant
    }
}
```

## Vault / ERC4626 Invariants

Use for vaults, staking shares, yield aggregators, LST wrappers.

### Invariants

```text
sum(userRedeemableAssets) <= vault.realAssets + allowedRounding
totalShares == sum(userShares)
previewDeposit/deposit and previewRedeem/redeem differ only by allowed rounding/fees
donation cannot decrease an existing user's redeemable assets
last withdrawer cannot leave bad accounting for next depositor
```

### Handler actions

- deposit
- mint
- withdraw
- redeem
- transfer shares
- donate underlying directly
- report strategy gain/loss if permissionless or modeled as environment event
- rebase/FOT behavior only if token type is in scope

### Ghost variables

- total assets deposited by users
- total assets withdrawn by users
- total external rewards/losses
- per-user fair share if needed

### Strong assertion targets

```solidity
assertLe(sumRedeemable, realAssets + tolerance, "claims exceed real assets");
assertGe(userRedeemableAfter, userRedeemableBefore - allowedLoss, "user lost value from unrelated action");
```

## Lending Invariants

### Invariants

```text
for each user: debtValue <= collateralValue * maxLTV after non-liquidation actions
totalDebt == sum(userDebt) within interest rounding
liquidation cannot target healthy accounts
protocolBadDebt == 0 after normal borrow/repay/withdraw flows
```

### Handler actions

- deposit collateral
- withdraw collateral
- borrow
- repay
- accrue interest
- update oracle within allowed rules
- liquidate only through public path

### Strong assertion targets

```solidity
assertLe(userDebtValue, userMaxBorrowValue, "user borrowed beyond LTV");
assertEq(protocolBadDebt, 0, "bad debt created by normal actions");
```

## Rewards / Staking Invariants

### Invariants

```text
totalClaimed + sum(claimable) <= totalRewardsFunded + allowedRounding
late stakers cannot claim rewards from periods before stake
unstaked users have no remaining voting/boost power unless explicitly documented
emergency exit leaves no monetizable claim/debt/vote state
```

### Handler actions

- stake
- stakeFor
- transfer stake token/share
- notifyRewardAmount/fund rewards if permissionless or modeled event
- checkpoint/updateIndex
- claim/claimFor/batchClaim
- unstake/emergencyWithdraw

### Strong assertion targets

```solidity
assertLe(totalClaimed + sumClaimable(), totalFunded + tolerance, "rewards over-distributed");
assertEq(votingPowerOfExitedUsers(), 0, "exited user kept voting power");
```

## Bridge Invariants

### Invariants

```text
releasedOrMinted[messageId] <= lockedOrBurned[messageId]
message state is exactly one of pending/finalized/refunded/cancelled
finalized messages cannot be retried or cancelled
refunded messages cannot be finalized
destination minted total <= source locked/burned total after decimals normalization
```

### Handler actions

- send/lock/burn
- relay/finalize
- retry
- cancel/refund
- malicious receiver callback if receiver is attacker-controlled

### Strong assertion targets

```solidity
assertLe(destinationMinted, sourceLockedNormalized, "bridge minted more than locked");
assertFalse(isFinalized[id] && isRefunded[id], "message finalized and refunded");
```

## AMM / DEX Invariants

### Invariants

```text
pool invariant cannot decrease except allowed fees/rounding
LP claims <= reserves
fee growth cannot be claimed twice for same liquidity/time range
router minOut/deadline constraints hold for every path
```

### Handler actions

- add/remove liquidity
- swap exact in/out
- collect fees
- callback payment
- sync/skim if public

### Strong assertion targets

```solidity
assertGe(kAfter, kBefore, "pool invariant decreased unexpectedly");
assertLe(sumLpClaims(), reserve0 + reserve1Value, "LP claims exceed reserves");
```

## Perps / Margin Invariants

### Invariants

```text
after any non-liquidation action, account margin >= maintenance margin
funding is applied before position size or margin changes
sum positive PnL claims <= pool collateral + sum negative PnL
healthy account cannot be liquidated
```

### Handler actions

- deposit/withdraw margin
- open/increase/decrease/close position
- update price
- accrue funding
- liquidate

### Strong assertion targets

```solidity
assertGe(accountMargin, maintenanceMargin, "unsafe account after normal action");
assertFalse(liquidatedHealthyAccount, "healthy account liquidated");
```

## Governance Invariants

### Invariants

```text
snapshot voting power cannot be changed after snapshot
queued proposal cannot execute before eta
cancelled proposal cannot execute
same voting signature cannot count twice
```

### Handler actions

- transfer/delegate
- propose
- vote/signature vote
- queue
- cancel
- execute
- advance time/blocks

### Strong assertion targets

```solidity
assertEq(votesAtSnapshotAfterTransfer, votesAtSnapshotBeforeTransfer, "snapshot changed retroactively");
assertFalse(executedCancelledProposal, "cancelled proposal executed");
```

## Account Abstraction / AI Wallet Invariants

### Invariants

```text
session key can only call allowed targets/selectors/values within time and spend limits
one userOp authorization cannot execute twice
paymaster balance cannot decrease for invalid/unauthorized operations beyond documented charge
untrusted content cannot create sign/submit/tool call without explicit policy approval
```

### Handler actions

- validate userOp
- execute allowed call
- batch/multicall
- spend session allowance
- paymaster sponsor/postOp
- feed untrusted AI content then request transaction

### Strong assertion targets

```solidity
assertLe(sessionSpent[key], sessionLimit[key], "session key exceeded spend limit");
assertFalse(executedForbiddenTarget, "session key executed forbidden target");
```

## Invariant Quality Rules

- Invariants must protect accepted impacts, not style preferences.
- Handler actions should model normal attacker-accessible behavior.
- Ghost accounting must be simpler and more obviously correct than protocol accounting.
- Every invariant failure needs minimization into a readable PoC before reporting.
- If a fuzz failure relies on out-of-scope malicious tokens/roles, mark `KILL` or document why in scope.
