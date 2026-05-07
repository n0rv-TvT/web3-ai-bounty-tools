# X-Ray Pre-Audit Workflow

Purpose: build a high-signal pre-audit map before hunting. This workflow is inspired by public Web3 audit-skill patterns such as Pashov Audit Group's `x-ray` approach, adapted for this local Opencode Web3 hunter.

X-ray output is not a finding report. It is a structured lead-generation map.

## Outputs

Create an `x-ray/` folder in the audited project when the user asks for `/web3-xray` or when a full-repo audit needs prep.

Recommended files:

```text
x-ray/x-ray.md              # concise pre-audit summary and verdict
x-ray/code-index.json       # machine-readable contract/storage/function/callgraph index
x-ray/entry-points.md       # full entry point and flow path map
x-ray/invariants.md         # guard, single-contract, cross-contract, economic invariant catalog
x-ray/architecture.json     # machine-readable architecture graph
x-ray/architecture.md       # human-readable architecture if SVG generation is not used
x-ray/git-risk.md           # git security analysis and hotspots
```

## Step 1: Enumerate And Measure

Determine project root and source dir:

- Foundry: read `foundry.toml`, prefer configured `src`.
- Hardhat: inspect `hardhat.config.*`, prefer `contracts/`.
- If unclear: try `src/` and `contracts/`.

Collect:

- Solidity files excluding `interfaces/`, `mocks/`, `test/`, `lib/`, `node_modules/` where appropriate.
- nSLOC and file count.
- test files and test function count.
- fuzz/invariant/formal configs: Foundry invariants, Echidna, Medusa, Certora, Halmos, Hevm.
- deployment scripts and deployment manifests.
- docs/spec/whitepaper/architecture files.

Local helper:

```bash
bash <skill-dir>/scripts/enumerate_web3.sh <project-root> [src-dir]
```

Coverage rule: test existence comes from file enumeration. Coverage command failure does not mean there are no tests.

## Step 2: Code Index And Entry Point Extraction

Build the machine-readable index first. It provides a shared source of truth for contracts, storage variables, public/external functions, modifiers, call edges, value movement, and lead-generation risk signals.

Local helper:

```bash
python3 <skill-dir>/scripts/code_indexer.py <project-root> --out x-ray/code-index.json
```

If the target uses `contracts/`, pass `--src-dir contracts`. If auditing deployment scripts or harnesses, pass `--include-tests` intentionally.

For every external/public non-view/non-pure function, record:

```text
Contract.function
Access: permissionless | role-gated | admin-only | initializer
Caller model:
Parameters and trust level:
Modifiers and inline msg.sender checks:
State modified:
Value flow: in | out | both | none
External calls:
Reentrancy guard:
Downstream call chain:
```

Important classification rules:

- `nonReentrant` is not access control.
- A function with no modifier but an inline `msg.sender` check is role-gated, not permissionless.
- `initializer`/`reinitializer` functions are one-shot deployment/upgrade surfaces; track separately.
- Grep/function-signature results are only candidates; verify function bodies before classification.

Local helper:

```bash
python3 <skill-dir>/scripts/entrypoint_scan.py <project-root> --json x-ray/entrypoints.json
```

The helper is intentionally conservative and imperfect. Use its output to prioritize manual reads.

## Step 3: Flow Path Construction

For major user-facing/value-moving entry points, build prerequisite chains:

```text
deposit collateral -> borrow -> accrue interest -> liquidate
request withdraw -> queue matures -> claim
send bridge message -> relay -> finalize -> retry/cancel
stake -> checkpoint -> notify reward -> claim -> unstake
```

For each path, note:

- required previous state
- who can move the path forward
- where time/oracle/external dependency changes are consumed
- where accounting updates happen
- where external calls happen before/after state changes

## Step 4: Invariant Catalog

Build four sections in `invariants.md`.

### G-N: Enforced Guards Reference

Quote guards that reference persistent storage:

```text
G-1
Location:
Predicate:
Purpose:
```

Guards are not bugs by themselves. They are map anchors.

Local helper:

```bash
python3 <skill-dir>/scripts/invariant_extract.py <project-root> --json x-ray/invariants-raw.json
```

Prioritize variables with multiple writers and uneven guard coverage.

### I-N: Single-Contract Invariants

Derive from:

- delta-write pairs: `totalSupply += shares`, `balanceOf[user] += shares`
- guard lifts: storage bounds that must hold across all write sites
- one-shot transitions: `require(addr == 0); addr = newAddr`
- temporal constraints: storage timestamp/block comparisons
- NatSpec/global invariant comments

For every lifted invariant, check all write sites. A single unguarded write site becomes a high-signal `LEAD`.

### X-N: Cross-Contract Invariants

Record assumptions where one contract consumes another contract's state or return value:

```text
Caller assumes oracle price is fresh.
Vault assumes strategy reported assets are current.
Router assumes market validates slippage.
Bridge assumes endpoint verified peer.
```

Include both caller-side assumption and callee-side write/update path.

### E-N: Economic Invariants

Higher-order properties derived from I-N/X-N:

- total user claims cannot exceed real assets
- destination minted cannot exceed source locked
- bad debt must remain zero after normal flows
- total claimed + claimable <= total funded rewards

## Step 5: Docs And Spec Extraction

Extract security-relevant claims only:

- global invariants
- actor definitions
- trust assumptions
- cross-system flows
- economic properties
- key design decisions

Tag spec-derived claims as `(per spec)` until code-verified.

High-signal output: contradictions between docs and code become `LEAD`, not findings.

## Step 6: Git Risk Analysis

Inspect current branch only.

Look for:

- recent changes in value-moving code
- commits mentioning fix, bug, audit, security, exploit, vuln, reentrancy, oracle, rounding, nonce, replay, upgrade
- files changed frequently or late in the branch
- dependencies copied/forked from upstream
- TODO/FIXME/HACK/temporary comments in security-sensitive code
- test co-change rate around dangerous commits

Local helper:

```bash
python3 <skill-dir>/scripts/git_risk.py <project-root> --json x-ray/git-risk.json
```

Turn git signals into lead priorities:

```text
High-risk changed area + value-moving entry point + weak tests = top hunt target
```

Do not claim a vulnerability from git history alone.

## Step 7: X-Ray Verdict

End with a readiness verdict:

- `LOW RISK TO AUDIT`: small surface, clear invariants, tests exist, few external dependencies.
- `MEDIUM RISK TO AUDIT`: normal DeFi complexity, some docs/tests gaps, manageable scope.
- `HIGH RISK TO AUDIT`: many value paths, weak tests, upgrades/bridges/oracles, dangerous late changes.
- `UNKNOWN`: insufficient source/docs/build context.

The verdict directs hunting effort; it is not a security certification.

## Lead Conversion

Every x-ray gap must become one of:

```text
LEAD: needs manual trace
PROVE: exploit path likely; write PoC
CHAIN REQUIRED: weak alone
KILL: no impact/reachability/scope
```

Never submit x-ray output directly as a bug bounty report.
