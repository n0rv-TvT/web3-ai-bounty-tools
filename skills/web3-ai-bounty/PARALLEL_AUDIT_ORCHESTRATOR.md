# Parallel Audit Orchestrator

Purpose: run the same code through different attacker lenses, then deduplicate and validate. This follows the useful pattern of multi-agent Solidity audit skills while keeping this hunter's stricter bounty gate and PoC-first discipline.

Use for `/web3-parallel-audit` after scope and x-ray/surface mapping.

## Mode Selection

Choose the smallest scope that can still prove impact.

- **Targeted mode**: 2-5 hot contracts or files the user specifies. Prefer this when debugging a lead or recent diff.
- **Subsystem mode**: one protocol area such as vault, oracle, router, bridge, staking, rewards, governance, or AI-agent tooling.
- **Full-repo mode**: only after x-ray/surface mapping, because broad context lowers per-function depth.

Default excludes:

- interfaces unless interface mismatch is the lead
- vendored libraries unless modified
- mocks and tests unless test/deploy logic is in scope
- generated files, build artifacts, caches

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

Bundle discipline:

- Create one shared source bundle when the agent environment supports local temp files.
- Print line counts for the source bundle and each lens bundle.
- Do not paste huge source bundles into every prompt when a file path can be referenced.
- Include a peripheral manifest of related files that lenses may read on demand.
- If the bundle is too large, split by subsystem and run the same lens sequence per subsystem.

## Audit Lenses

Run these lenses in parallel when tooling supports subagents. If not, run them sequentially as mental passes.

### 1. Vector Scan Lens

Goal: match known attack vectors to code constructs.

Focus:

- protocol-specific vector list
- missing guard or partial guard
- reachable construct
- repeat pattern across sibling contracts

Required behavior: when one pattern is confirmed in one contract, search siblings for the same pattern before final output.

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

## Shared Lens Rules

Each lens must obey these rules:

- Treat scanner output and model ideas as leads only.
- Check both `functionName` and `_functionName` naming variants.
- Weaponize a confirmed pattern across sibling functions/contracts.
- Escalate a bug to its worst realistic impact, but do not invent chains.
- One vulnerability per item. Same root cause = one item. Different fixes or assets = separate items.
- Admin-only functions doing admin things are not findings unless the bug is privilege bypass or unsafe delegated authority.
- No proof means `LEAD`, not `FINDING`.
- If a concrete guard blocks the exact claimed step, reject or demote immediately.

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

Optional but useful fields:

```text
preconditions: <minimal state required>
normal_attacker: yes/no
impact_asset: <funds/state/data/signing/tool>
kill_condition: <exact source/test condition that would kill this item>
```

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

## Refutation-First Gate Evaluation

Before the 7-question bounty gate, run each deduplicated item through four refutation-first gates. Later gates are not evaluated for failed items.

### Gate 1 — Refutation

Construct the strongest argument that the finding is wrong.

- Quote the guard/check/constraint that blocks the claimed step.
- If a concrete source-level refutation blocks the path, mark `KILL` or demote to `LEAD` if a code smell remains.
- Speculative refutation is not enough to kill.

### Gate 2 — Reachability

Prove the vulnerable state is achievable in the reviewed code/deployment model.

- Structurally impossible → `KILL`.
- Requires privileged action outside normal operation → `CHAIN_REQUIRED` or `NA_RISK`.
- Achievable through normal usage/common token behavior → continue.

### Gate 3 — Trigger

Prove a normal attacker or realistic actor can execute the attack.

- Only trusted role can trigger → demote unless privilege bypass is the bug.
- Attack cost exceeds extraction and no accepted freeze/privilege impact → `NA_RISK` or `KILL`.
- Normal attacker can trigger → continue.

### Gate 4 — Impact

Prove material harm to an identifiable victim/protocol/security boundary.

- Self-harm only → `KILL`.
- Dust-only/no compounding/no accepted severity category → `NA_RISK`.
- Concrete stolen funds, frozen funds, bad debt, unauthorized privileged action, sensitive data leak, account takeover, or unsafe signing/tool execution → continue.

## Bounty Gate Evaluation

Run each item that survives refutation through the strict 7-question gate once.

Important rules:

- Multiple lenses agreeing is not proof.
- Concrete source-level refutation wins.
- No deployer-intent reasoning; evaluate what current code allows, then check docs/scope for intended behavior.
- `UNCERTAIN` is not report-ready. It can be `LEAD` or `CHAIN_REQUIRED`, not `REPORT_READY`.
- Evaluate constructor → initializers → setters → core value-moving functions → emergency paths → callbacks in a fixed pass. Do not repeatedly revisit until a preferred answer appears.

## Confidence And Promotion

Use confidence only for prioritization, not report-readiness.

Start at 100 for source-traced, PoC-plausible issues. Deduct:

- partial attack path: -20
- bounded non-compounding impact: -15
- specific but achievable state: -10
- missing duplicate/intended-behavior check: -10
- no control test where practical: -5

Promotion rules:

- `LEAD` can become `PROVE` when the complete exploit chain is source-traced or two independent lenses converge with no concrete refutation.
- Multi-lens agreement never overrides a concrete source-level block.
- `REPORT_READY` still requires the PoC/evidence/report gates, regardless of confidence.

## Final Ranking

Sort candidates:

1. Direct theft / bad debt / unauthorized privileged action.
2. Signature replay / bridge double release / upgrade takeover.
3. Accounting desync with exact victim loss.
4. Accepted frozen funds with duration/no recovery.
5. Weak leads requiring chain.

Then write PoC for the best `PROVE` candidate only.
