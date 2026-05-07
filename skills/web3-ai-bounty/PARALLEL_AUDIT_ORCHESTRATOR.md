# Parallel Audit Orchestrator

Purpose: run the same code through different attacker lenses, then deduplicate and validate. This follows the useful pattern of multi-agent Solidity audit skills while keeping this hunter's stricter bounty gate.

Use for `/web3-parallel-audit` after scope and x-ray/surface mapping.

## Source Bundle

Prepare one concise source bundle:

```text
scope summary
protocol type
in-scope source files
entry point map
invariants summary
docs/spec assumptions
known exclusions
```

Exclude by default:

- tests unless testing logic is in scope
- mocks
- interfaces except where interface mismatch is suspected
- vendored libraries unless modified
- generated files

## Audit Lenses

Run these lenses in parallel when tooling supports subagents. If not, run them sequentially as mental passes.

### 1. Vector Scan Lens

Goal: match known attack vectors to code constructs.

Focus:

- protocol-specific vector list
- missing guard or partial guard
- reachable construct
- repeat pattern across sibling contracts

### 2. Math Precision Lens

Goal: exploit rounding, precision, decimal, cast, and scale bugs.

Focus:

- every division in value-moving path
- wrong rounding direction
- zero-rounding with dust
- decimal mismatch
- downcast and multiplication overflow
- ERC4626 preview/execute mismatch

### 3. Access Control Lens

Goal: break roles, modifiers, initialization, upgrades, confused deputies.

Focus:

- every writer of sensitive state
- weakest writer guard
- initializer/reinitializer paths
- role grant/revoke chains
- delegatecall/proxy authority
- contracts holding approvals or privileged execution rights

### 4. Economic Security Lens

Goal: exploit external dependency, token behavior, incentives, and atomic capital.

Focus:

- oracle failures and manipulation
- fee-on-transfer/rebasing/blacklisting/void-return tokens
- flash-loanable sequences
- capacity starvation
- dependency failures blocking withdrawals/liquidations/claims

### 5. Execution Trace Lens

Goal: break assumptions across ordered calls and state transitions.

Focus:

- parameter divergence
- stale reads
- partial updates
- special sentinels
- cross-transaction interleaving
- approval residuals
- message/queue lifecycle bugs

### 6. Invariant Lens

Goal: find conservation, coupling, and equivalence breaks.

Focus:

- all writers of both sides of invariant
- path divergence
- boundary states
- cap enforcement on every write path
- emergency transitions

### 7. Periphery Lens

Goal: audit helper contracts/libraries/wrappers that core trusts.

Focus:

- encoders/decoders
- assembly byte-width
- provider wrappers
- existence checks
- hidden side effects
- return-value assumptions

### 8. First-Principles Lens

Goal: ignore named bug classes and violate the code's own assumptions.

Focus:

- extract assumption per state-changing function
- identify who controls assumption inputs
- construct sequence where assumption is false
- monetize corrupted state

## Required Output Schema

Every lens must output structured blocks only.

```text
FINDING | contract: <Name> | function: <func> | bug_class: <kebab-tag> | group_key: <Contract | function | bug-class>
path: <caller -> function -> state change -> impact>
proof: <concrete values/trace/state sequence from actual code>
description: <one sentence>
fix: <one sentence>
```

```text
LEAD | contract: <Name> | function: <func> | bug_class: <kebab-tag> | group_key: <Contract | function | bug-class>
code_smells: <observed code smell>
description: <what remains unverified>
next_check: <exact check or PoC step>
```

No proof means LEAD, not FINDING.

## Deduplication

Group by:

```text
Contract | function | bug-class
```

Merge synonymous bug classes if same function and same root cause.

Keep the best proof. Annotate agent count as `[lenses: N]`.

## Chain Detection

Only create a composite chain when:

```text
finding A output creates finding B precondition
AND combined impact is strictly worse than either alone
AND both are independently reachable
```

Most audits have 0-2 valid chains. Do not invent chains to make weak leads look strong.

## Gate Evaluation

Run each deduplicated item through the strict 7-question gate once.

Important rules:

- Multiple lenses agreeing is not proof.
- Concrete source-level refutation wins.
- No deployer-intent reasoning; evaluate what current code allows, then check docs/scope for intended behavior.
- `UNCERTAIN` is not report-ready. It can be `LEAD` or `CHAIN REQUIRED`, not `REPORT`.

## Final Ranking

Sort candidates:

1. Direct theft / bad debt / unauthorized privileged action.
2. Signature replay / bridge double release / upgrade takeover.
3. Accounting desync with exact victim loss.
4. Accepted frozen funds with duration/no recovery.
5. Weak leads requiring chain.

Then write PoC for the best `PROVE` candidate only.
