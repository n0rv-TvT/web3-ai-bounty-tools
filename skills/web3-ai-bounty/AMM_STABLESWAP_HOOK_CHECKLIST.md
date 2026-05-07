# AMM, StableSwap, and Uniswap v4 Hook Checklist

Use this module when the target contains AMMs, stable swap curves, concentrated liquidity, routers, pool managers, hooks, liquidity accounting, swap callbacks, or fee accumulators.

Goal: do not stop after direct-theft checks. In `medium-bounty` and `audit-review` modes, continue through boundary-driven issues that contests often accept: reachable panic reverts, stuck withdrawals, invariant non-convergence, hook semantic mismatches, bricked pools, quote/execution divergence, and material in-scope DoS/freeze.

## Mode Calibration

Before triage, record:

```yaml
amm_mode:
  severity_mode: critical-bounty|medium-bounty|audit-review|learning
  accepted_impact_classes: []
  excluded_impact_classes: []
  accepts_temporary_freeze_or_dos: true|false|unknown
  accepts_low_info: true|false|unknown
  private_bounty_default: true|false
```

Mode rules:

- `critical-bounty`: pursue direct loss, permanent or accepted freeze, insolvency, bad debt, privileged action, or unsafe signing. Mark weak DoS/griefing as `NA_RISK` unless explicitly accepted.
- `medium-bounty`: investigate concrete temporary freeze, stuck withdrawals, bounded accounting loss, periphery path failure with user impact, reachable invariant break, or material pool bricking.
- `audit-review`: keep `AUDIT_NOTE` and `LOW_INFO` separately from bounty leads.
- `learning`: explain what was proven, killed, or left as exercise.

## Required Output Fields

Every AMM lead must include:

```yaml
lead:
  status: LEAD|PROVE|CHAIN_REQUIRED|NEEDS_CONTEXT|NEEDS_SCOPE_CONFIRMATION|DUPLICATE|NA_RISK|KILL|AUDIT_NOTE|LOW_INFO
  source_pointer: "<file:contract:function>"
  pool_type: constant-product|stable-swap|concentrated-liquidity|hybrid|uniswap-v4-hook|router|unknown
  attacker_capability: "<swap/add/remove/flash/callback/donate/direct-call/etc>"
  affected_asset: "<token/share/liquidity/reward/accounting state>"
  invariant: "<x*y, stable invariant, liquidity, fee growth, balances, hook delta, quote/execution>"
  exploit_sequence: []
  assertion_target: "<profit/loss/freeze/panic/bricked pool/bad accounting>"
  kill_condition: "<check/revert/invariant/test that refutes it>"
  evidence_missing: []
  next_action: "<exact command or stop reason>"
```

## High-Signal Queues

### 1. Direct interfaces before router assumptions

Check whether router protections are absent from pool/vault direct calls:

- `swap`, `deposit`, `mint`, `addLiquidity`, `removeLiquidity`, `burn`, `skim`, `sync`, `collect`, `donate`, `settle`, `take`, `unlock`, `lockAcquired`, `flash`, `callback`.
- Slippage, recipient, deadline, pause, allowlist, and hook permission checks in router but not direct pool path.
- Quote functions that assume router-only rounding or transfer order.

Promote to `PROVE` only when a normal caller reaches the direct path and can assert value movement, accepted freeze, or state corruption.

### 2. Stable invariant and convergence boundaries

Test or reason with exact numbers for:

- zero liquidity, one-sided near-zero liquidity, first LP, last LP.
- highly imbalanced pools.
- amplification coefficient near min/max or update boundary.
- token decimal mismatch: 6/18, 8/18, >18, mixed precision.
- convergence loop max-iteration behavior and non-convergence revert/panic.
- rounding direction across invariant calculation, LP mint/burn, swap out, admin fee, protocol fee.
- invariant after fee-on-transfer, rebasing, or direct donation.

Accepted Medium/audit-review targets can include reachable panic reverts, non-convergence that bricks swaps/withdrawals, or deterministic user loss from rounding/precision.

### 3. Initial liquidity and empty-pool boundaries

Check:

- first LP can set price, invariant, or virtual price incorrectly.
- first LP mints zero or excessive LP shares.
- donations before first mint or after last burn affect share price.
- min-liquidity lock assumptions fail with decimals or stable invariant math.
- empty pool can be initialized through a periphery path that skips checks.
- last withdrawal leaves residual balances or non-zero accounting that blocks reinitialization.

Kill if only dust and no compounding, freeze, or accepted impact class exists.

### 4. Quote-vs-execution consistency

Compare every quote/preview path with execution:

- `getAmountOut` vs `swap`.
- `previewDeposit`/`previewMint` vs add liquidity.
- `previewWithdraw`/`previewRedeem` vs remove liquidity.
- off-chain quoter assumptions vs hook-modified execution.
- fee rounding in quote vs execution.
- transfer-before-callback vs transfer-after-callback state.

Promote when the mismatch can bypass slippage, extract value, force bad debt, or create accepted freeze. Mark `AUDIT_NOTE` if it is only UI confusion without on-chain impact.

### 5. Oracle, rate, and virtual-price boundaries

Check:

- stale or same-block reserves used for valuable decisions.
- virtual price manipulation by donation, flash liquidity, imbalance, or delayed fee collection.
- rate providers with stale, zero, negative-like, downscaled, or revert behavior.
- Chainlink/Pyth/adapter decimals mixed with pool decimals.
- TWAP accumulator overflow, timestamp wrap, or zero elapsed time.
- oracle update triggered before/after swap in exploitable order.

Do not report generic spot-oracle use unless there is an executable economic path.

### 6. Token behavior matrix

For each in-scope token assumption, test or reason:

- fee-on-transfer.
- rebasing or ERC4626 share-price movement.
- ERC777 or ERC1363 callbacks.
- no-return/false-return ERC20.
- blacklist/pause tokens.
- tokens with >18 or unusual decimals.
- transfer hooks that reenter pool/periphery.
- token balance can be donated directly to pool.

In `critical-bounty`, mark non-standard-token-only leads as `NA_RISK` unless the program explicitly includes those tokens/behaviors and impact is material.

### 7. Callback, unlock, and reentrancy ordering

For Uniswap v4-style systems and callback-based AMMs, map:

- `lock`/`unlock` state.
- `beforeSwap`, `afterSwap`, `beforeAddLiquidity`, `afterAddLiquidity`, `beforeRemoveLiquidity`, `afterRemoveLiquidity`.
- callback sender checks and pool key validation.
- transient storage assumptions.
- whether hooks can call back into pool manager, router, token, or accounting functions.
- state updates before/after external hook calls.

Promote only if the callback changes outcome: wrong delta, stale accounting, bypassed authorization, extracted funds, bricked pool, or accepted freeze.

### 8. Uniswap v4 hook return-delta semantics

For hooks using return deltas:

- Verify hook permissions match implemented return values.
- Compare `beforeSwapReturnDelta` and `afterSwapReturnDelta` signs against exact token direction.
- Check `specifiedAmount` sign handling for exact-input vs exact-output swaps.
- Confirm deltas are settled/taken once and cannot be double-counted.
- Check negative deltas with unsigned casts, `int128`/`int256` truncation, and abs/min edge cases.
- Ensure hook cannot make pool manager/accounting believe tokens were paid when they were not.
- Check paths where hook returns a delta but caller/router ignores it.

Assertion targets:

- attacker receives tokens without paying equivalent input.
- pool manager debt/accounting remains non-zero or incorrectly zero.
- LP fee growth/reserves become inconsistent.
- swap consistently reverts/bricks for normal users when accepted by scope.

### 9. Multi-token shared reserves and asset-index bugs

Check stable pools and baskets for:

- wrong token index after sorting or pool-key construction.
- duplicate token entries.
- token A accounting updated with token B decimals/rate.
- one asset paused/blacklisted causing all withdrawals to brick.
- shared reserve accounting across pools, gauges, or wrappers.
- admin fee or protocol fee credited to wrong asset.

Promote when wrong-index accounting causes fund loss, stuck funds, bad debt, or accepted freeze.

### 10. Residual balances, fees, and accumulator boundaries

Check:

- residual balances after swap/add/remove/settle/take.
- protocol fee/admin fee rounding to zero or accumulating unclaimable dust into material value.
- `feeGrowthGlobal`, per-position fee growth, reward per liquidity, or stable swap admin fees with signed/unsigned casts.
- `int128`/`uint128` boundaries for liquidity, deltas, and fee accumulators.
- fee-on-transfer causing balance delta smaller than accounting delta.

Kill if the maximum impact is unclaimable dust with no compounding and no accepted severity category.

## Skip / Do Not Waste Time

Do not spend PoC time on these unless chained to concrete accepted impact:

- generic zero-address findings.
- style/gas/naming issues.
- scanner-only warnings.
- admin-can-rug or owner centralization.
- theoretical MEV/frontrunning if excluded.
- dust-only rounding without compounding or freeze.
- non-standard token behavior outside program scope.

## Minimal PoC Shapes

Prefer one of these:

1. `test_control_honestSwapOrLiquidityWorks` + `test_exploit_attackerExtractsValue`.
2. `test_control_quoteMatchesExecution` + `test_exploit_quoteExecutionMismatchBypassesSlippage`.
3. `test_control_withdrawAfterBalancedLiquidity` + `test_exploit_imbalancedPoolBricksWithdrawals`.
4. `test_control_hookDeltaSettlesOnce` + `test_exploit_hookDeltaDoubleCountsOrSkipsPayment`.
5. `test_control_feeAccumulatorNormalRange` + `test_exploit_feeAccumulatorCastBoundaryBreaksAccounting`.

Each PoC must assert the exact attacker gain, victim/protocol loss, frozen funds/duration, bad debt, unauthorized state change, or deterministic accepted DoS/freeze. No assertion means no `REPORT_READY`.
