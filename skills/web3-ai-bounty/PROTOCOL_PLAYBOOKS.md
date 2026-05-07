# Web3 Protocol-Specific Hunting Playbooks

Purpose: generic bug classes are useful, but real bugs are protocol-shaped. Use this file after surface mapping to switch into the target's protocol mode.

For every protocol type:

1. Draw the asset lifecycle.
2. Name the accounting invariant.
3. Identify attacker-controlled timing/order.
4. Generate exploit hypotheses.
5. Select the shortest PoC target.

## 1. Lending / Borrowing / Liquidation

### Asset lifecycle

```text
deposit collateral -> value collateral -> borrow debt asset -> accrue interest -> repay/withdraw -> liquidate if unsafe
```

### Crown jewels

- collateral valuation
- debt accounting
- interest index updates
- liquidation eligibility and seize amount
- oracle freshness and decimals
- reserve/factor accounting

### Core invariants

- A user cannot borrow more than allowed by collateral value and LTV.
- `totalDebt` must match sum of borrower debt plus accrued interest rules.
- Liquidation cannot seize more value than allowed by close factor/bonus.
- A healthy position cannot be liquidated.
- Protocol must not end with bad debt after price normalizes.

### High-signal questions

- Can collateral be overvalued by stale/spot/decimal-bug oracle?
- Can debt be undercounted by stale borrow index or skipped accrual?
- Can attacker withdraw collateral before debt/loss/index update?
- Does repay-on-behalf or repay-with-collateral skip accounting?
- Does partial liquidation round in attacker's favor?
- Does batch liquidation miss a health check present in single liquidation?
- Can collateral token behavior be fee-on-transfer/rebasing/non-standard?

### Best PoC targets

- borrow over limit, price normalizes, protocol has bad debt
- liquidate healthy victim and profit
- withdraw collateral while debt remains undercounted
- repay less than debt due to rounding/index mismatch

## 2. ERC4626 Vault / Yield Aggregator / Strategy Vault

### Asset lifecycle

```text
deposit assets -> mint shares -> strategy invests -> harvest/loss report -> redeem shares -> withdraw assets
```

### Crown jewels

- share price calculation
- `totalAssets()` source of truth
- strategy debt/loss reporting
- preview vs actual execution
- deposit/mint and withdraw/redeem symmetry

### Core invariants

- User redeemable assets are proportional to shares after fees/losses.
- Total user claims cannot exceed real assets plus legitimate strategy assets.
- Direct donations cannot let attacker steal victim deposits.
- Strategy loss cannot be avoided by exiting before report when the loss is already economically realized.

### High-signal questions

- What happens when `totalSupply == 0`?
- Can first depositor donate to inflate share price?
- Does `deposit()` validate differently from `mint()`?
- Does `withdraw()` burn shares before or after transfer?
- Does `totalAssets()` include manipulable balance or stale strategy report?
- Can strategy report gains/losses after attacker enters/exits?
- Do share transfers update reward/lock/vote checkpoints?

### Best PoC targets

- first depositor donation steals victim deposit
- attacker exits before loss report and shifts loss to remaining users
- attacker enters before harvest and captures prior yield
- preview says safe amount, execution mints/burns different value

## 3. AMM / DEX / Router / Concentrated Liquidity

### Asset lifecycle

```text
add liquidity -> swap -> fee accrual -> remove liquidity -> collect fees
```

### Crown jewels

- reserve accounting
- invariant math
- fee growth indexes
- tick/liquidity accounting
- router slippage/deadline/path validation
- callback settlement

### Core invariants

- Swaps must preserve pool invariant after fees.
- LP share of reserves/fees must be proportional to liquidity.
- Callback must pay exact owed token amounts before state assumes settlement.
- Router cannot bypass slippage/deadline/user recipient checks.

### High-signal questions

- Can a callback reenter before reserves/liquidity update?
- Does router validate path tokens and recipient?
- Is slippage checked on every route, including exact-output/multicall/batch?
- Can fee growth be claimed twice after liquidity move?
- Can zero liquidity/tick boundary create rounding profit?
- Can `sync`/`skim`/donation alter price used by another component?

### Best PoC targets

- reentrant swap callback drains or misprices pool
- router path bypass sends output to attacker or ignores minOut
- fee growth checkpoint bug double-claims fees
- spot reserve used as oracle creates bad debt elsewhere

## 4. Perpetuals / Options / Margin / Funding

### Asset lifecycle

```text
deposit margin -> open position -> funding/PNL accrues -> modify/close -> liquidation/settlement
```

### Crown jewels

- margin health
- PnL calculation
- funding index
- oracle price and confidence
- liquidation and settlement price

### Core invariants

- Trader cannot withdraw margin needed to support open positions.
- Funding and PnL cannot be skipped by modifying/closing through alternate paths.
- Liquidation only happens below maintenance margin.
- Settled PnL cannot exceed pool collateral.

### High-signal questions

- Is funding applied before every position-size/margin change?
- Can same-block oracle update and liquidation liquidate healthy users?
- Does partial close round PnL/funding in attacker's favor?
- Are long/short signs handled symmetrically?
- Can stale price settle options/perps unfairly?
- Can batch close/liquidate skip per-position checks?

### Best PoC targets

- attacker withdraws margin before funding/PnL update and leaves bad debt
- liquidates healthy victim via stale/manipulated price
- repeated partial close extracts rounding profit
- settlement uses stale price to overpay attacker

## 5. Bridge / Cross-Chain Messaging / OFT

### Asset lifecycle

```text
source lock/burn -> message emitted -> relay/verify -> destination mint/release -> retry/cancel/refund on failure
```

### Crown jewels

- message uniqueness
- consumed/refunded/finalized flags
- trusted remote/domain verification
- token decimals and representation
- retry/cancel/finalize ordering

### Core invariants

- A message can release/mint value at most once.
- Source refund and destination release cannot both succeed.
- Destination minted/released cannot exceed source locked/burned.
- Message domain cannot be confused across chain/app/receiver.

### High-signal questions

- Is consumed flag set before external calls?
- Do retry, cancel, and finalize share the same state machine?
- Is message ID bound to source chain, destination chain, sender, receiver, nonce, and payload?
- Can failed message be retried after refund?
- Can nonblocking receive hide failure while source considers transfer complete?
- Are decimals normalized across chains?

### Best PoC targets

- finalize same message twice
- cancel/refund source and retry/finalize destination
- forged/trusted-remote mismatch releases funds
- callback reenters before message consumed

## 6. Staking / Rewards / veToken / Gauges

### Asset lifecycle

```text
stake/lock -> checkpoint -> rewards accrue -> vote/boost -> claim -> unstake/unlock
```

### Crown jewels

- reward index
- user checkpoint
- boost/voting weight
- lock duration and early exit
- gauge weight distribution

### Core invariants

- Total claimed plus remaining claimable cannot exceed funded rewards.
- Rewards for prior stakers cannot be captured by late entrants.
- Votes/boosts must track current ownership/locks.
- Emergency exit cannot leave claim/vote power behind.

### High-signal questions

- Can attacker deposit after reward transfer but before index update?
- Do transfer/stakeFor/batch paths update checkpoints?
- Does emergency withdraw skip reward/vote/lock cleanup?
- Can someone claim on behalf with stale receiver/accounting?
- Can gauge weight be poked/reset by anyone at a favorable time?

### Best PoC targets

- late entrant captures old rewards
- share/NFT transfer keeps old boost or voting power
- emergency exit withdraws principal and still claims rewards
- permissionless checkpoint shifts rewards between cohorts

## 7. Liquid Staking / Restaking / Withdrawal Queue

### Asset lifecycle

```text
deposit ETH/token -> mint LST/shares -> validator/restaking strategy -> rewards/slashing -> request withdraw -> queue -> claim
```

### Crown jewels

- exchange rate
- pending withdrawals
- slashing/loss accounting
- queue ordering and claimability
- validator/operator trust assumptions

### Core invariants

- LST supply must be backed by assets minus slashing/loss.
- Withdrawal claims cannot exceed reserved assets.
- Queue order and claim amount cannot be manipulated by later users.
- Slashing/loss cannot be avoided by exiting before report when economically realized.

### High-signal questions

- Can direct donation alter exchange rate?
- Can attacker request withdrawal before slashing report and avoid loss?
- Can queue claim use stale exchange rate?
- Can same withdrawal NFT/claim be transferred and claimed twice?
- Can operator/admin recovery make issue N/A under scope?

### Best PoC targets

- loss shifted to remaining holders
- withdrawal claim overpays after exchange-rate change
- duplicate claim through transfer/retry/cancel path
- first depositor/share inflation in LST wrapper

## 8. Governance / Timelock / Delegation

### Asset lifecycle

```text
token/ve power -> delegate -> propose -> vote -> queue -> execute -> cancel
```

### Crown jewels

- proposal threshold
- vote snapshot
- delegation checkpoints
- timelock delay
- executor permissions
- upgrade/admin actions

### Core invariants

- Voting power at snapshot cannot be changed retroactively.
- Queued operation cannot execute before delay or after cancellation.
- Proposal execution target/value/data cannot be changed after vote.
- Delegation/transfer cannot double-count votes.

### High-signal questions

- Are checkpoints updated on transfer/mint/burn/delegate?
- Can proposal calldata be altered after voting?
- Can cancel and execute race or disagree?
- Can anyone execute arbitrary queued operations?
- Can signature votes replay across proposals/chains/contracts?

### Best PoC targets

- double vote through transfer/delegation bug
- execute cancelled/expired proposal
- bypass timelock delay
- replay signed vote/delegation

## 9. Account Abstraction / Smart Wallet / Paymaster / Session Keys

### Asset lifecycle

```text
userOp/session key -> validate -> paymaster sponsors -> wallet executes calls -> nonce/accounting updates
```

### Crown jewels

- nonce model
- userOp hash/domain
- session key permissions
- paymaster validation and postOp accounting
- wallet call target/value/data policy

### Core invariants

- One signed userOp/session authorization cannot execute outside its policy.
- Session key cannot exceed target/value/function/time/spend limits.
- Paymaster cannot be drained by invalid or replayed operations.
- Wallet summary/approval must match executed calldata.

### High-signal questions

- Is userOp bound to chain, entrypoint, wallet, nonce, and calldata?
- Do batch/multicall paths bypass session-key limits?
- Can delegatecall escape target allowlist?
- Does paymaster charge after execution even on revert?
- Can nonce be reused across validation modes?

### Best PoC targets

- replay userOp or session action
- session key executes forbidden call through batch/delegatecall
- paymaster balance drained by sponsored failing operations
- AI/wallet summary mismatch signs harmful calldata

## 10. AI Wallet / AI Trading Agent / Tool-Using Web3 Assistant

### Asset lifecycle

```text
user prompt + context + untrusted content -> model decision -> tool call / transaction build / signature / submission
```

### Crown jewels

- signing boundary
- transaction submission boundary
- tool permissions
- user confirmation UI
- memory and cross-user data
- API/RPC/signing secrets

### Core invariants

- Untrusted content cannot authorize a transaction/tool call.
- Model output cannot bypass explicit user confirmation for harmful actions.
- Tool calls cannot exceed user/session permission.
- Private data and secrets cannot cross users or be included in model output/tool calls.

### High-signal questions

- What untrusted text does the agent read before signing/submitting?
- Can token/NFT metadata/proposal text alter recipient/amount/calldata?
- Can a low-privilege user trigger backend/admin/MCP tools?
- Does transaction summary exactly decode target/value/data?
- Is memory partitioned by user/wallet/session?
- Are secrets ever available to model context or tool outputs?

### Best PoC targets

- indirect prompt injection causes harmful approval/transfer/signature
- UI summary says safe action while calldata approves attacker
- cross-user memory leaks wallet labels/portfolio/secrets
- prompt/tool injection invokes privileged backend action
