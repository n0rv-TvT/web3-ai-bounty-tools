# Web3 Exploit Hypothesis Engine

Purpose: make the agent good at finding bugs by forcing it to generate attacker hypotheses from concrete capabilities, state transitions, and broken invariants. Use this before deep PoC work and whenever scanner output feels noisy.

## Core Model

A real bug usually needs all five parts:

```text
Attacker capability + reachable function + broken assumption + ordered steps + concrete impact
```

If any part is missing, the lead is not report-ready.

## Exploit Sentence Template

Write leads as complete exploit sentences:

```text
Because <actor> can <capability> in <function> while <state/assumption> is <stale/missing/desynced>, attacker can <step 1>, <step 2>, and <step 3>, causing <fund theft/frozen funds/bad debt/unauthorized action/data leak>.
```

Examples:

```text
Because any user can call claimFor() while rewardIndex is updated only after transfer, attacker can deposit after rewards arrive, call claimFor(attacker), and withdraw, causing rewards funded by prior stakers to be paid to the attacker.

Because signed withdrawals omit chainId and verifyingContract, attacker can reuse Alice's L2 withdrawal signature on another market clone, causing unauthorized release of escrowed funds.

Because finalizeMessage() marks messages consumed after token transfer, attacker can reenter through a malicious receiver and finalize the same message twice, causing double release from the bridge escrow.
```

If you cannot write this sentence with a specific accepted impact, mark `KILL` or `CHAIN_REQUIRED`.

## Capability Matrix

For each crown-jewel component, fill the attacker capabilities.

| Capability | Entry point | Sensitive state touched | External calls | Possible impact | Lead? |
|---|---|---|---|---|---|
| deposit/mint | | shares/assets | token transfer | share inflation/accounting desync | |
| withdraw/redeem | | shares/assets/debt | token transfer | theft/frozen funds/bad debt | |
| claim/reward update | | index/claimable | token transfer | reward theft | |
| borrow/repay/liquidate | | debt/collateral | oracle/AMM | bad debt/bad liquidation | |
| checkpoint/harvest/settle | | epoch/index/PnL | strategy/oracle | value shift | |
| sign/submit/cancel order | | nonce/order status | token transfer | replay/theft | |
| bridge retry/cancel/finalize | | message consumed/refunded | token transfer/callback | double mint/release/freeze | |
| initialize/upgrade | | owner/roles/implementation | delegatecall | takeover | |
| AI tool call | | wallet/session/policy | signer/backend tool | unsafe signing/data leak | |

## Attacker-Controlled Inputs To Abuse

For every public/external function, mark what attacker controls:

- `amount`: try 0, 1, dust, max, rounding boundary, exact threshold, fee-on-transfer amount.
- `recipient`: attacker contract, victim, zero address, protocol address, token contract, callback receiver.
- `token`: malicious ERC20, ERC777, fee-on-transfer, rebasing, no-return token, token with custom decimals, token already in vault.
- `time`: same block, before/after epoch, before/after oracle update, before/after harvest, before/after loss report.
- `order`: deposit before update, withdraw before loss, trigger after donation, cancel before finalize, retry after refund.
- `signature`: reuse, wrong function, wrong chain, wrong market, expired, cancelled, malleated if applicable.
- `calldata`: packed collision, selector confusion, arbitrary target, delegatecall target, AI-generated transaction payload.
- `state precondition`: empty vault, first depositor, last withdrawer, paused, initialized/uninitialized, stale oracle, zero liquidity.

## Invariant Breaker Prompts

Ask these against every important invariant:

### Value Conservation

```text
Can attacker make assets leave without burning the right shares/debt/claim?
Can attacker mint shares/claims without transferring fair assets?
Can direct token balance change affect share price or collateral value?
```

### User Isolation

```text
Can attacker's action reduce victim redeemable assets, collateral, rewards, votes, or withdrawal priority?
Can attacker choose timing to move losses/rewards between cohorts?
```

### Replay Safety

```text
Can one authorization cause two state changes?
Can an authorization for context A work in context B?
Can cancellation/fill/retry/finalize disagree on consumed state?
```

### Privilege Safety

```text
Can normal attacker reach a function intended for owner/keeper/router/vault?
Can a public helper mutate state that privileged flows assume protected?
Can init/upgrade/role-setting be called after deployment?
```

### External Call Safety

```text
What invariant is false during the external call?
Can callback enter a sibling with stale state?
Can read-only reentrancy observe an inflated/deflated rate?
```

### AI/Tool Safety

```text
Can untrusted text influence tool selection, calldata, recipient, amount, or confirmation summary?
Can low-privilege user input reach backend/admin tools?
Can memory or tool output cross users?
```

## Lead Scoring Matrix

Score each lead quickly. Spend PoC time on the highest scores.

| Category | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| Impact | none/dust | inconvenience | accepted freeze/limited loss | direct theft/bad debt/privileged action/data leak |
| Reachability | dead/admin-only | unusual setup | normal user but constraints | any normal attacker |
| PoC simplicity | unclear | complex fork only | local/fork feasible | minimal deterministic test |
| Scope | out | uncertain | likely in | exact contract/function in scope |
| Novelty | known/intended | likely duplicate | not seen yet | recent change/unique path |
| Economic realism | impossible | needs huge capital | flash/fork realistic | profitable/simple |

Deductions:

- `-5`: explicit exclusion applies.
- `-4`: requires compromised admin/operator/key.
- `-3`: docs say intended/accepted risk.
- `-2`: no measurable victim/protocol harm.
- `-2`: only scanner output.
- `-1`: requires fragile mempool/frontrunning if excluded.

Decision:

- `13+`: `PROVE` now.
- `9-12`: `PROVE` if top lead; otherwise keep as lead.
- `5-8`: `CHAIN_REQUIRED` or narrow check only.
- `<5`: `KILL`.

## 15-Minute Lead Triage Loop

For each lead, timebox proof planning:

1. Name attacker capability.
2. Name victim/protocol state harmed.
3. Name exact accepted impact category.
4. Name minimal test setup.
5. Name final assertion.

If this cannot be done in 15 minutes, mark `CHAIN_REQUIRED` or `KILL` and move on.

## Counterexample-Driven Auditing

For every important invariant, actively construct counterexamples.

Example:

```text
Invariant: totalAssets equals assets claimable by all shares.
Counterexample attempts:
- direct donation before victim deposit
- strategy loss before user withdraw
- fee-on-transfer deposit
- rebase between preview and execute
- emergency withdraw skips share burn
```

The best PoCs are counterexamples with balances attached.

## Good Lead Output Format

Use this exact format when presenting leads:

```text
Lead L-01: <short title>
State: PROVE | CHAIN_REQUIRED | NEEDS_CONTEXT | NEEDS_SCOPE_CONFIRMATION | NA_RISK | KILL
Exploit sentence: Because ...
Impacted invariant:
Attacker capability:
Victim/protocol harm:
Expected assertion:
Scope/exclusion risk:
Next action:
```
