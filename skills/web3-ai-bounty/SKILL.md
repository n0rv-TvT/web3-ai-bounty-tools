---
name: web3-ai-bounty
description: Web3 and AI bug bounty workflow for smart contract audits, DeFi protocols, wallets, agents, tool-using AI systems, Foundry PoCs, validation, and report drafting.
license: MIT
compatibility: opencode
metadata:
  category: security
  workflow: bug-bounty
---

# Web3 AI Bug Bounty Workflow v2

Use this skill at the start of any Web3, DeFi, wallet, bridge, smart contract, or AI-agent bug bounty session.

Mission: find exploitable, in-scope, high-impact bugs and prove them with minimal runnable PoCs. Think like an attacker, report like an auditor. Never assume; verify against source code, tests, docs, deployed bytecode, or read-only live state.

The goal is not to list risks. The goal is to produce validated findings with concrete evidence of stolen funds, frozen funds, bad debt, unauthorized privileged action, account takeover, sensitive data exposure, or unsafe signing/tool execution.

## Hard Rules

- Confirm program scope before testing public assets or deployed contracts.
- Never use real private keys, seed phrases, user funds, or irreversible production actions.
- Do not broadcast transactions unless the user explicitly asks and confirms authorization.
- Prefer local tests, fork simulations, static analysis, and read-only RPC calls.
- Do not modify production contract code during audit work unless explicitly asked to patch. Add tests, harnesses, scripts, notes, or reports instead.
- Do not call a lead a finding until it has scope match, reachability, concrete impact, and a working PoC.
- Kill scanner-only output, theoretical issues, best-practice gaps, missing comments, style issues, dead code, and findings requiring privileged compromise unless the program explicitly pays for them.
- If intended behavior, docs, prior audits, exclusions, or recovery mechanisms make the lead weak, say so and move on.

## Required Audit Artifacts

For non-trivial audits, create or maintain these artifacts. Use the bundled templates when helpful:

- `AUDIT_WORKBOOK_TEMPLATE.md`: scope brief, attack surface map, assumption ledger, invariants, leads, validation notes.
- `FINDING_PLAYBOOK.md`: high-signal exploit loops for turning contract surfaces into PoC-ready leads.
- `HYPOTHESIS_ENGINE.md`: attacker-capability matrix, exploit sentence templates, lead scoring, and fast kill rules.
- `POC_PATTERN_LIBRARY.md`: bug-class-specific PoC shapes and assertion targets.
- `PROTOCOL_PLAYBOOKS.md`: protocol-type playbooks for lending, vaults, AMMs, perps, bridges, staking, liquid staking, governance, account abstraction, and AI wallets.
- `ADVERSARIAL_TEST_HARNESS.md`: reusable malicious token, receiver, oracle, strategy, bridge, and signer harness patterns for proving or killing leads quickly.
- `INVARIANT_FACTORY.md`: protocol-specific invariant templates for Foundry, Echidna, Medusa, and Halmos workflows.
- `REAL_BUG_CASEBOOK.md`: paid-bug shapes, accepted-impact patterns, and weak variants that usually get rejected.
- `X_RAY_PREAUDIT_WORKFLOW.md`: pre-audit x-ray process for entry points, invariants, architecture, docs, tests, and git-risk signals.
- `CODE_INDEX_ENGINE.md`: Solidity source indexer for contracts, storage variables, public/external functions, modifiers, callgraph edges, value movement, and lead-generation risk signals.
- `PARALLEL_AUDIT_ORCHESTRATOR.md`: multi-lens audit swarm, finding schema, deduplication, and gate review.
- `ATTACK_VECTOR_TRIAGE.md`: vector-driven audit queue with skip/drop/investigate/prove/kill classification.
- `ATTACK_VECTOR_DB.md`: local protocol-grouped attack-vector database used by `/web3-vectors`.
- `AUDIT_REPORT_MINING.md`: workflow for mining public audit reports and turning prior findings into target-specific hypotheses.
- `REPORT_MINING_SOURCES.md`: public report sources and query patterns for protocol-specific mining.
- `LEAD_DATABASE_ENGINE.md`: production JSON lead database schema, lifecycle, CLI, validation rules, metrics, and artifact links.
- `LEAD_MEMORY_TEMPLATE.md`: project-local memory template for proven/killed leads and faster future triage.
- `SCANNER_NORMALIZATION.md`: scanner-output ingestion rules for Slither, Aderyn, Mythril/MythX-style, Semgrep, and generic JSON.
- `ONCHAIN_VERIFICATION.md`: read-only deployed-state verification workflow using RPC, EIP-1967 proxy slots, Sourcify, explorers, source matching, balances, and value-at-risk checks.
- `RPC_CONFIG.md`: safe RPC environment variables, Foundry fork patterns, and EIP-1967 slots.
- `STANDARDS_MAPPING.md`: SWC, OWASP Smart Contract Top 10, EthTrust, SCSVS, OpenZeppelin, and best-practice mapping.
- `LANGUAGE_MODULES.md`: Solidity, Vyper, Solana/Anchor, CosmWasm, ink!, and Stylus audit modules.
- `VULNERABILITY_MODULES.md`: deep modules for reentrancy, math, access control, oracles, signatures, bridges, ERC4626, AA, and AI.
- `scripts/`: executable helper scripts for lead database management, x-ray enumeration, entry-point scanning, invariant extraction, git-risk analysis, scanner normalization, read-only on-chain verification, and Foundry PoC scaffold generation.
- `evals/`: intentionally vulnerable mini-protocol fixtures for testing the hunter against known bug shapes.
- `FOUNDRY_POC_TEMPLATE.md`: human-readable Foundry exploit/control test skeleton.
- `FOUNDRY_POC_GENERATOR.md`: Lead DB/on-chain/code-index driven Foundry fork/local PoC scaffold generator with pattern mapping and harness insertion.
- `VALIDATION_GATE_TEMPLATE.md`: pre-report validation checklist.
- `REPORT_TEMPLATE.md`: impact-first report format.

Keep findings in one of these states:

- `LEAD`: interesting signal, not proven.
- `PROVE`: code path looks reachable; build PoC.
- `CHAIN REQUIRED`: standalone impact is weak; needs another bug or condition.
- `KILL`: no reachability, intended behavior, excluded, duplicate, scanner-only, or no concrete impact.
- `REPORT`: passed validation with working PoC and in-scope impact.

## Evidence Ladder

Do not skip levels:

1. Scanner or grep signal.
2. Manual source confirmation.
3. Reachability from normal attacker privileges.
4. State transition or external call sequence that violates an invariant.
5. Runnable PoC with assertions.
6. Program scope and exclusion check.
7. Duplicate/intended-behavior check.
8. Report.

## Phase 0: Target Value And Scope Triage

Before deep work, answer:

- What program is this and what assets are in scope?
- What is the maximum realistic payout and is it worth the time?
- What chains, deployed addresses, proxy addresses, and implementation addresses are in scope?
- What impact categories are accepted verbatim by the program?
- What exclusions are listed verbatim by the program?
- Is mainnet/fork testing allowed? Are live transactions forbidden?
- Are admin/operator recovery paths considered valid mitigation by the program?

Score target quality:

- TVL above 10M USD: +2
- Critical bounty above 50K USD: +2
- Current version lacks top-tier audit: +2
- Recently deployed or recently upgraded: +1
- Upgradeable proxies: +1
- Source available with NatSpec/docs: +1
- Familiar protocol type: +1

Decision:

- 0-3: skip or do only a quick high-signal pass unless user insists.
- 4-5: narrow audit around crown jewels and recent changes.
- 6+: full workflow.

Also compute `max_realistic_payout = min(10% * TVL, program_cap)`. If below 10K USD, warn that effort may not be worth it.

Use the `web3_audit_target_score` MCP tool when enough target data is available.

## Phase 1: Protocol Brief Before Deep Code Reading

Before line-by-line auditing, build a one-page target brief from docs, README, scope, deploy scripts, tests, and high-level source layout:

- What does the protocol do in one sentence?
- What assets does it hold and how can they move?
- Who are the privileged roles and what can they do?
- What external contracts, oracles, bridges, tokens, signers, keepers, relayers, or AI tools does it trust?
- What is the trust model between components?
- What are the crown jewels: withdrawals, accounting, oracle inputs, liquidations, rewards, upgrades, bridge messages, signatures, permissions, signing tools?
- What prior audits, changelogs, issues, or disclosed reports already mention similar behavior?
- What commit, release tag, deployment block, or bytecode version is being audited?

If the repo is local, inspect project files first: `foundry.toml`, `hardhat.config.*`, `package.json`, `remappings.txt`, `src/`, `contracts/`, `test/`, `script/`, `deployments/`, `broadcast/`, docs, audits, and deployment manifests.

Use `web3_audit_project_fingerprint` and `web3_audit_contract_surface` when available.

## Phase 2: Attack Surface Mapping

For every contract, classify its role:

- token, vault, router, controller, oracle, bridge, governance, staking, rewards, escrow, strategy, factory, proxy, implementation, library, signer/verifier, AI agent/tool boundary.

For every external/public function, record:

- Who can call this?
- What state does it read?
- What state does it write?
- What assets can move?
- What external calls does it make and in what order?
- Does it rely on stale balance, stale oracle, stale index, block timestamp, same-block ordering, or off-chain signer assumptions?
- What modifiers protect it and do siblings have the same protection?
- Can the order of operations be exploited?

Map sensitive state:

- accounting: `totalAssets`, `totalSupply`, `totalShares`, `totalDebt`, `assets`, `shares`, `balances`, `debt`, `liquidity`, `reserves`.
- rewards/indexes: `accRewardPerShare`, `rewardPerToken`, `index`, `cumulative`, `lastUpdate`, `epoch`, `checkpoint`.
- permissions: owner, roles, guardians, keepers, operators, signers, timelocks, multisigs, pausers.
- replay boundaries: nonces, deadlines, domain separators, chain IDs, verifying contracts, salts, order IDs.
- oracle boundaries: price, confidence, staleness, TWAP window, fallback source, decimal normalization.
- upgrade boundaries: initializer, reinitializer, storage layout, admin, implementation lock.

Most important rule: read all sibling functions. If `deposit()` has a guard, inspect `mint()`. If `withdraw()` updates accounting, inspect `redeem()`, `emergencyWithdraw()`, batch versions, callbacks, and admin paths. If `vote()` is guarded, inspect `poke()`, `reset()`, and delegation paths.

Use `web3_audit_modifier_matrix` and `web3_audit_sibling_modifier_report` to find modifier and guard mismatches.

## Phase 2.5: Protocol-Specific Hunting Mode

After the generic surface map, classify the target by protocol type and load the corresponding section in `PROTOCOL_PLAYBOOKS.md`:

- lending / borrowing / liquidation
- ERC4626 vault / yield aggregator / strategy vault
- AMM / DEX / router / concentrated liquidity
- perpetuals / options / margin / funding
- bridge / cross-chain messaging / OFT
- staking / rewards / veToken / gauges
- liquid staking / restaking / LST / withdrawal queues
- governance / timelock / delegation
- account abstraction / smart wallet / paymaster / session keys
- AI wallet / AI trading agent / tool-using Web3 assistant

For each protocol type, use its asset-flow map, accepted invariants, exploit questions, and PoC targets. Generic checklists are not enough; protocol-specific accounting and lifecycle assumptions are where high-value bugs usually hide.

## Phase 2.75: X-Ray Pre-Audit Mode

When the target is a full repo, run an x-ray before hunting: enumerate code, classify entry points, synthesize invariants, map architecture, extract docs/spec assumptions, inspect test coverage signals, and analyze git history for dangerous late changes or security fix hotspots. Use `X_RAY_PREAUDIT_WORKFLOW.md`.

When available, use the local helper scripts from this skill directory:

```bash
bash scripts/enumerate_web3.sh <project-root> [src-dir]
python3 scripts/code_indexer.py <project-root> --out x-ray/code-index.json
python3 scripts/entrypoint_scan.py <project-root> --json x-ray/entrypoints.json
python3 scripts/invariant_extract.py <project-root> --json x-ray/invariants-raw.json
python3 scripts/git_risk.py <project-root> --json x-ray/git-risk.json
```

Script output is a lead generator. Verify important classifications manually before PoC work.

The x-ray output should create hunting artifacts, not final findings:

- permissionless and role-gated entry points
- machine-readable contract/storage/function/callgraph index
- value-moving flow paths
- invariant catalog with guard/write-site gaps
- architecture and external dependency map
- protocol-type threat profile
- tests/fuzz/formal verification gaps
- git-risk hotspots and recent dangerous-area changes

Attach `x-ray/code-index.json` to `audit-leads.json` as a `code-index` artifact when using the Lead Database. Turn every x-ray gap into `LEAD`, then run the hypothesis engine before PoC work.

## Phase 2.8: Lead Database Mode

For non-trivial audits, maintain `audit-leads.json` in the target repo root using `LEAD_DATABASE_ENGINE.md` and `<skill-dir>/scripts/lead_db.py`. This file is the system of record; Markdown notes are secondary.

Initialize once per target:

```bash
python3 <skill-dir>/scripts/lead_db.py init audit-leads.json --target "<program/protocol>" --protocol <type> --repo .
```

Record every scanner/x-ray/manual signal as `LEAD` or `INTAKE`; never write it as a report-ready finding. Promote only after evidence improves:

```bash
python3 <skill-dir>/scripts/lead_db.py add audit-leads.json --title "<impact path>" --bug-class <class> --file <file> --contract <contract> --function <function>
python3 <skill-dir>/scripts/lead_db.py update-status audit-leads.json L-0001 PROVE --reason "manual trace shows normal attacker reachability"
python3 <skill-dir>/scripts/lead_db.py add-poc audit-leads.json L-0001 --path test/Exploit.t.sol --command "forge test --match-test test_exploit -vvvv" --status PASS
python3 <skill-dir>/scripts/lead_db.py set-gate audit-leads.json L-0001 --in-scope --reachable --normal-attacker --normal-victim --concrete-impact --working-poc --duplicate-intended-checked --promote
python3 <skill-dir>/scripts/lead_db.py validate audit-leads.json
```

Database enforcement mirrors the bounty discipline: `KILL` needs a reason, `CHAIN_REQUIRED` needs chain requirements, and `REPORT_READY` requires a passing PoC plus all seven validation questions true. Use `/web3-leads` when working through Opencode.

## Phase 3: Cross-File Assumption Hunting

Unique bugs usually live between files. Build an assumption ledger:

```text
Assumption: <what contract A assumes>
Made in: <file/function>
Relied on by: <file/function>
Violated by: <file/function or condition>
Impact if false: <fund loss/freeze/bad debt/privilege/data impact>
Status: LEAD | PROVE | CHAIN REQUIRED | KILL | REPORT
```

For every assumption in file A, find where file B violates it:

- Interface A requires X. Does every caller of A provide X?
- Contract A validates Y at deploy time. Does runtime still assume Y after upgrades, oracle changes, role changes, or token behavior changes?
- Contract A updates state before an external call. Does B assume the whole operation is atomic?
- Permission granted in A. Is it broader than what docs or B expect?
- Router checks slippage. Do direct market/vault functions also check slippage?
- Vault assumes token balance equals accounting. Can strategy, donation, fee-on-transfer, rebasing, rescue, or callback paths desync it?
- Signature verifier assumes domain separation. Can another function, chain, market, or contract reuse the signed payload?

This phase is mandatory before report drafting. A single-file issue is often a false positive until cross-file assumptions are checked.

## Phase 3.5: Exploit Hypothesis Engine

After mapping the surface, do not wait for scanners to tell you what matters. Use `HYPOTHESIS_ENGINE.md` to generate concrete exploit sentences from attacker capabilities and broken invariants.

For every crown-jewel component, produce at least five hypothesis sentences in this form:

```text
Because <actor> can <capability> in <function> while <state/assumption> is <stale/missing/desynced>, attacker can <ordered steps> causing <accepted impact>.
```

Then score each lead for impact, reachability, PoC simplicity, scope match, novelty, and economic realism. Pick the highest scoring `PROVE` lead and write the PoC. If no hypothesis can name attacker gain, victim/protocol loss, unauthorized action, bad debt, accepted freeze duration, or data exposure, kill it.

## Phase 4: Boundary Conditions And Ordering

For every important variable and code path, test or reason through:

- zero
- one / minimum viable amount
- max uint256 or near-overflow
- `totalSupply == 0`
- empty vault / first depositor / last withdrawer
- time has not advanced
- two operations in the same block
- stale oracle update
- partial fill / partial repay / partial liquidation
- paused/unpaused transitions
- upgrade before/after initialization
- fee-on-transfer, rebasing, ERC777 hooks, ERC721/1155 callbacks, non-standard ERC20 return values

Ask ordering questions:

- Is state updated before or after token transfer/external call?
- Can a callback observe stale state?
- Can a permissionless trigger move accounting across epochs or checkpoints?
- Can a user enter after funds arrive but before accrual/snapshot?
- Can a user exit before debt/reward/loss is applied?

## Phase 4.5: Language-Specific Module Selection

Classify contract languages before tool selection. Use `LANGUAGE_MODULES.md`:

- Solidity/EVM: Foundry, Slither, Aderyn, Wake, Echidna, Medusa, Halmos.
- Vyper/EVM: Vyper compiler, Ape/Titanoboa, Slither where supported, Semgrep.
- Rust/Solana/Anchor: Cargo, Anchor, Trident, Mollusk, LiteSVM, cargo-audit/deny/geiger.
- Rust/CosmWasm: Cargo, cw-multi-test, cargo-audit/deny.
- Rust/ink!/Stylus: cargo contract / cargo stylus, ABI/storage-boundary checks.

Language-specific issues still need the same impact proof: stolen funds, frozen funds, bad debt, unauthorized privileged action, account takeover, sensitive data exposure, or unsafe signing/tool execution.

## Phase 5: Tool Pipeline

Tools create leads, not findings. Run narrow commands first, then expand.

When MCP tools are available, prefer:

- `web3_audit_tool_status`
- `web3_audit_project_fingerprint`
- `web3_audit_contract_surface`
- `web3_audit_pattern_scan`
- `web3_audit_modifier_matrix`
- `web3_audit_sibling_modifier_report`
- `web3_audit_bug_class_checklist`
- `web3_audit_invariant_template`
- `web3_audit_foundry_poc_template`
- `web3_audit_validation_gate`
- `web3_audit_report_template`
- `web3_audit_safe_tool_run`

Recommended local commands when present:

```bash
forge build
forge test
forge test -vvvv
forge inspect <Contract> storage-layout
forge inspect <Contract> methods
slither .
slither . --json slither-results.json
aderyn .
solhint 'src/**/*.sol' 'contracts/**/*.sol'
semgrep --config=p/security-audit .
```

For fuzzing, invariants, or symbolic exploration when the repo supports them:

```bash
echidna .
medusa fuzz
halmos
```

For code graphing when useful:

```bash
surya describe <files>
surya graph <files>
solidity-code-metrics <files>
wake detect
```

If a scanner emits a result, manually answer:

- Is the vulnerable line reachable by an unprivileged or normally privileged attacker?
- What exact state or balance changes?
- What accepted impact category does this match?
- Can I write a minimal PoC today?

If not, mark `KILL` or `CHAIN REQUIRED`.

When scanners produce JSON, normalize them first with `SCANNER_NORMALIZATION.md`:

```bash
python3 <skill-dir>/scripts/scanner_normalize.py slither-results.json semgrep.json \
  --tool auto \
  --code-index x-ray/code-index.json \
  --json normalized-scanner-report.json \
  --leads-json normalized-scanner-leads.json
python3 <skill-dir>/scripts/lead_db.py import-scanner audit-leads.json normalized-scanner-report.json
```

Normalized scanner rows are `LEAD`, `CHAIN_REQUIRED`, or suppressed as `KILL`; they are never report-ready until manually proven.

## Phase 5.5: Parallel Audit Swarm

For medium/large targets, run `PARALLEL_AUDIT_ORCHESTRATOR.md` after x-ray/surface mapping. Split the same source bundle across audit lenses: vector scan, math precision, access control, economic security, execution trace, invariants, periphery, and first principles.

Each lens must output structured `FINDING` or `LEAD` blocks with proof fields. Deduplicate by `contract | function | bug_class`, merge chainable issues only when combined impact is strictly worse, and run validation gates once per deduplicated item. Multiple agents agreeing is a confidence signal, not proof; concrete refutation wins.

## Phase 5.75: Attack Vector Triage

Use `ATTACK_VECTOR_TRIAGE.md` and `ATTACK_VECTOR_DB.md` to classify relevant known vectors before deep manual work. For every vector, choose exactly one: `SKIP`, `DROP`, `INVESTIGATE`, `PROVE`, or `KILL`.

Do not grind every vector blindly. Match vectors to protocol type, entry points, assets, and integrations. Investigate only vectors with reachable construct + missing/partial guard + plausible accepted impact.

## Phase 5.9: Standards Mapping

Use `STANDARDS_MAPPING.md` to tag validated findings with SWC/OWASP/EthTrust/SCSVS/OpenZeppelin references. Standards improve explanation and remediation, but never replace impact proof. Do not submit a finding just because it violates a standard.

## Phase 5.95: On-Chain And RPC Verification

For deployed/in-scope targets, use `ONCHAIN_VERIFICATION.md` and `RPC_CONFIG.md` before report drafting:

```bash
python3 <skill-dir>/scripts/onchain_verify.py <address> \
  --chain-id <id> \
  --rpc-env <CHAIN_RPC_ENV> \
  --token <asset> \
  --json onchain.json
```

Verify deployed bytecode, proxy implementation, admin/owner, roles where possible, source verification via Sourcify/explorer, token balances, oracle state, and value at risk. Attach the output to Lead DB as an `onchain` artifact. On-chain data supports validation; a local/fork PoC is still required for reports.

## Phase 6: High-Value Bug Class Checklist

Check these explicitly on every audit. Prefer paid-impact classes over style issues.

For active hunting, use `FINDING_PLAYBOOK.md` as the operating manual. Do not passively scan. Pick a crown-jewel component, run the relevant exploit loops, write down the expected attacker/victim balance delta, then prove or kill the lead.

Before deep-diving a protocol type, use `AUDIT_REPORT_MINING.md` to mine public reports and prior paid-bug shapes from similar systems. Extract root causes and accepted impacts, then translate them into target-specific hypotheses. Do not report a copied bug shape unless the current code has its own reachable exploit path and PoC.

### Accounting State Desynchronization

Signals:

- `totalSupply`, `totalAssets`, `totalShares`, `totalDebt`, `rewardPerShare`, `accRewardPerShare`, `cumulative`, `index`, `shares`, `assets` updated inconsistently.
- Early returns in claim, redeem, withdraw, repay, unstake, settle, batch, or emergency paths.
- One path transfers tokens but skips state updates.
- One path updates state before a balance check that depends on old balances.
- Strategy harvest/loss/donation/rescue changes token balance without synchronizing accounting.

Questions:

- What invariant should always hold?
- Which functions increase/decrease each accounting variable?
- Does every fast path update the same state as the slow path?
- Who profits when accounting is stale?

### Access Control And Sibling Mismatches

Signals:

- One sibling has `onlyOwner`, `onlyRole`, `onlyVault`, `onlyKeeper`, `onlyNewEpoch`, `whenNotPaused`, ownership/approval checks while another does not.
- `_requireOwned(tokenId)` is used where owner-or-approved is required, or vice versa.
- Modifier uses `if` without `require`/`revert`.
- Public helper mutates sensitive state but is treated like view/internal.
- Initializers lack `initializer`, reinitializers are reusable, or implementations lack `_disableInitializers()`.

Impact must be unauthorized privileged action, fund movement, bad debt, or security-state corruption. Mere centralization is usually weak.

### Incomplete Code Paths

Compare create/update/cancel, deposit/mint/withdraw/redeem, borrow/repay/liquidate, bridge send/receive/retry/cancel, stake/unstake/claim/emergency.

Signals:

- Update decreases price/collateral without refund or revalidation.
- Cancel deletes state before external operations finish.
- Mint bypasses deposit validation.
- Partial fills refund wrong asset or wrong recipient.
- Emergency exits skip debt, reward, fee, lock, vote, or accounting cleanup.
- Batch path misses a check present in single-item path.

### Oracle And Price Manipulation

Signals:

- Chainlink `latestRoundData()` without `updatedAt`, `answeredInRound`, positive price, sequencer, and decimal checks.
- Pyth `getPriceUnsafe()` without confidence/freshness validation.
- Uniswap `slot0` or reserves used as spot price for valuable action.
- TWAP window too short for value protected.
- Fallback oracle is weaker and can be forced.
- Price normalization or token decimals are inconsistent.

Prove profit/bad debt/fund theft. Do not report generic oracle manipulation without an executable economic path.

### ERC4626 And Vault Share Bugs

Signals:

- First depositor / empty vault donation inflation.
- Rounding to zero shares or zero assets.
- Missing virtual assets/shares.
- Share transfer does not update lock, stake, vote, checkpoint, or reward records.
- `preview*` materially differs from execution.
- `totalAssets()` includes manipulable donations or excludes strategy loss.

Boundary tests: `totalSupply == 0`, one wei deposit, last withdrawal, direct donation, rebasing underlying.

### Reentrancy And Callback Bugs

Signals:

- State updates after `call`, `safeTransfer`, `safeTransferFrom`, ERC777 hooks, ERC721/1155 receiver hooks, DEX swaps, flash loan callbacks, strategy calls, bridge callbacks, or arbitrary tool calls.
- `nonReentrant` on one function but not a sibling touching the same state.
- Read-only reentrancy where a view reads stale reserves, shares, rates, or balances during callback.

Prove the callback changes outcome, not just that reentry is technically possible.

### Signature Replay And Off-Chain Authorization

Signals:

- `ecrecover`/`ECDSA.recover` without nonce, deadline, chain ID, verifying contract, action, market, token, amount, recipient, or domain separator.
- `abi.encodePacked` collisions in signed or hashed data.
- Signatures can be reused across chains, forks, functions, markets, orders, or contracts.
- Cancellation/fill paths do not consume nonces consistently.

PoC should replay the same signature twice or in the wrong context and prove unauthorized movement/state change.

### Proxy And Upgrade Bugs

Signals:

- Uninitialized proxy or implementation.
- Missing authorization in upgrade function.
- Storage collisions across proxy, implementation, and inherited contracts.
- Dangerous `delegatecall` target selection.
- Upgrade breaks accounting/oracle assumptions.
- Public `initialize` or `reinitialize` can be called after deployment.

Check deployed proxy and implementation state with read-only calls when possible.

### Bridge And Cross-Chain TOCTOU

Signals:

- Source-side action is not atomic with destination-side accounting.
- Message replay or retry can mint/release twice.
- Cancellation/refund can race finalization.
- Domain IDs, chain IDs, nonces, or trusted remotes are ambiguous.
- Delayed fulfillment is documented as intended; do not report it unless program accepts duration-based freezes and you prove the duration.

### Permissionless Triggers And MEV-Adjacent Bugs

Signals:

- Anyone can checkpoint, harvest, settle, liquidate, rebalance, update oracle, finalize epoch, or claim on behalf.
- Trigger can move value across users, epochs, tranches, or reward indexes.

Avoid excluded frontrunning/MEV framing unless the program accepts it. Focus on deterministic state corruption or direct value transfer.

## Phase 7: AI And Agentic Web3 Surface

Use this for AI agents, wallets, trading bots, transaction builders, MCP tools, chatbots, portfolio agents, natural-language signing flows, or AI-generated calldata.

Map what the AI can read:

- user wallet addresses, portfolio, balances, transaction history, labels, private notes
- API keys, RPC keys, session cookies, signing service tokens, secrets
- chat history or cross-user memory
- untrusted webpages, token metadata, NFT metadata, governance proposals, Discord/Telegram messages, PDFs, docs, URLs, markdown, HTML

Map what the AI can do:

- sign messages or transactions
- submit transactions
- simulate, swap, bridge, approve, transfer, borrow, lend, list orders, cancel orders
- change user settings, permissions, delegates, signers, policies, allowlists
- call backend/admin/MCP tools
- write memory or persist instructions

High-value AI bug classes:

- prompt injection causing unauthorized transaction generation, signing, submission, or tool call
- indirect prompt injection through token metadata/proposals/docs/URLs/chat history
- signing boundary bypass where calldata is generated/submitted without explicit user confirmation
- tool permission escalation where low-privilege input causes admin/backend tool use
- cross-user data exposure through memory, portfolio labels, chat history, or cached tool outputs
- secret leakage of private keys, seed phrases, API keys, RPC keys, signing tokens, cookies
- unsafe transaction summary where UI says safe action but calldata executes harmful action
- excessive agency: agent trades, approves, transfers, bridges, cancels, or changes permissions without confirmation
- output injection through AI-generated HTML, markdown, transaction notes, token names, or proposal text

AI finding rule: prompt injection alone is usually weak. It matters when it reaches harmful capability: signing, submitting transactions, leaking user data/secrets, invoking privileged tools, or changing security-sensitive state. Build the chain and prove the harmful action.

Use `web3_audit_ai_agent_threat_model` when capability booleans are known.

## Phase 8: Humanized Foundry PoC Standard

Convert only promising leads into executable tests.

For `PROVE` leads, use `FOUNDRY_POC_GENERATOR.md` to create a scaffold from Lead DB, Code Index, and on-chain verification artifacts, then manually fill exploit steps and assertions:

```bash
python3 <skill-dir>/scripts/foundry_poc_generator.py \
  --project-root . \
  --lead-db audit-leads.json \
  --lead-id L-0001 \
  --onchain onchain.json \
  --code-index x-ray/code-index.json \
  --out test/L0001Exploit.t.sol \
  --metadata test/L0001Exploit.plan.json
```

Generated exploit tests intentionally fail until completed. Never mark PoC `PASS` from a scaffold alone.

When a PoC needs hostile behavior, use `ADVERSARIAL_TEST_HARNESS.md` for reusable attacker components: fee-on-transfer tokens, rebasing tokens, no-return tokens, callback receivers, reentrant strategies, fake oracles, bridge receivers, and signer/replay helpers. Keep harnesses inside `test/`, `script/`, or `mock/`; do not alter production contracts unless explicitly asked to patch.

When a bug is stateful or timing-dependent, use `INVARIANT_FACTORY.md` to create a small invariant test first. A good invariant can reveal the shortest exploit sequence and make the final PoC easier.

Every PoC must follow this order:

1. Setup: deploy contracts or create fork, mint/fund balances, assign roles.
2. Baseline: assert honest state before attack.
3. Attack: execute exploit step by step.
4. Proof: assert exact attacker gain, victim loss, frozen funds, bad debt, unauthorized role/state change, or leaked data.
5. Control: add `test_control_*` showing honest path works or patched behavior would block the bug when practical.

Rules:

- Name actors like a story: `alice`, `attacker`, `victim`, `bridgeOperator`, `keeper`, `liquidator`. Avoid `addr1`, `user`, `account`.
- Comment every non-obvious line and every invariant break.
- Assert exact values where possible. Use approximate assertions only when precision/rounding requires it.
- Prove both sides: attacker gained and victim/protocol lost, or funds became unrecoverably frozen for the program-required duration.
- No real private keys or user funds.
- Do not hardcode fragile mainnet state. Use `vm.createFork(vm.envString("RPC_URL"), blockNumber)`. If using `vm.store`, document slot derivation clearly.
- Keep the PoC minimal. One exploit path, one control path, clear assertions.

Recommended test shape:

```solidity
function test_control_honestPathWorks() public {
    // Setup honest state.
    // Execute normal flow.
    // Assert expected balances/accounting.
}

function test_exploit_attackerStealsVictimFunds() public {
    // Setup
    uint256 attackerBefore = asset.balanceOf(attacker);
    uint256 victimBefore = asset.balanceOf(victim);

    // Baseline
    assertEq(vault.totalAssets(), expectedAssets, "baseline assets wrong");

    // Attack
    vm.startPrank(attacker);
    // exploit steps
    vm.stopPrank();

    // Proof
    uint256 attackerGain = asset.balanceOf(attacker) - attackerBefore;
    uint256 victimLoss = victimBefore - asset.balanceOf(victim);
    assertGt(attackerGain, 0, "attacker did not profit");
    assertEq(attackerGain, victimLoss, "attacker gain must equal victim loss");
}
```

Run narrow command first:

```bash
forge test --match-test test_exploit -vvvv
```

Then run relevant broader tests if needed:

```bash
forge test
```

## Phase 9: Strict Validation Gate

All seven answers must be YES before drafting a report:

1. Is the target and exact affected contract/function in scope?
2. Is the vulnerable code reachable in the current version or deployed bytecode?
3. Can an attacker exploit it now with normal privileges?
4. Does the victim take no unusual action beyond normal protocol use?
5. Is there concrete impact: stolen funds, frozen funds, bad debt, unauthorized privileged action, sensitive data leak, account takeover, or unsafe signing/tool execution?
6. Is there a working PoC with assertions proving the impact?
7. Did you check docs, README, prior audits, disclosed reports, changelog, GitHub issues/PRs, and hacktivity for duplicates or intended behavior?

If any answer is NO: do not report. Continue researching, mark `CHAIN REQUIRED`, or mark `KILL`.

Also run the four pre-submission gates:

### Technical Validity

- PoC passes with `forge test`, Jest, Hardhat, or relevant command.
- Contract addresses and implementations are verified when reporting deployed systems.
- Derived addresses, PDAs, salts, domains, and storage slots are derived from first principles.
- Affected function is actually in scope.

### Intended Behavior Check

- README/docs do not describe this behavior as intended.
- Queue, retry, pause, admin, or recovery mechanism does not make the issue safe or excluded.
- No assumed admin/operator unavailability if such action is documented.
- Prior audits do not list this as accepted risk/known limitation.

### Duplicate Risk Check

- Search public audits for this issue class/function.
- Search GitHub issues and PRs for related fixes.
- Search function name plus `vulnerability`, `bug`, `audit`, `fix`.
- Check public hacktivity/similar titles if available.

### Impact Accuracy And Scope Match

- Attacker profit, victim loss, frozen amount/duration, bad debt, privileged action, or data exposure is proven.
- Impact does not rely on privileged role unless privilege bypass is the bug.
- Impact matches the program's exact accepted category wording.
- Explicit exclusions do not apply: DoS-only, griefing-only, centralization, known limitation, MEV/frontrunning, low-impact dust, test-only code, out-of-scope chain/address.

Use `web3_audit_validation_gate` when ready.

## Phase 10: Report Drafting

Draft only after validation passes.

Title formula:

```text
[Bug class] in [contract/function] allows [actor] to [impact]
```

Report structure:

- Summary: impact first, then root cause.
- Affected components: contracts, functions, deployed addresses, chain, commit hash, proxy/implementation.
- Root cause: one clear sentence naming the missing check, bad ordering, stale state, bad invariant, or unsafe trust boundary.
- Steps to reproduce: PoC path and exact command.
- Impact: quantify funds, users, roles, bad debt, duration, or security state corruption.
- Remediation: one or two concrete code-level fixes.

Evidence-first wording:

- Avoid `could potentially`. Say `the PoC demonstrates` only when it does.
- Avoid leading with `griefing`. If valid, state measurable fund loss/freeze duration and recovery path absence.
- Avoid generic `DoS`. If valid, state exact frozen asset, duration, and program category.
- Avoid `theoretical`. If no PoC, do not report.
- Avoid excluded frontrunning/MEV framing unless accepted. Focus on deterministic exploit mechanics.
- Avoid `simulation` when using fork tests. Say `local fork execution against block <n>`.

Match the program's exact wording. If they require `temporary freezing > 1 hour`, prove duration. If they require `direct theft`, prove attacker receives funds. If they require `no admin recovery path`, prove admin cannot recover or that recovery is outside program assumptions.

## Default Slash-Command Behavior

When user asks for one of these workflows, behave as follows:

- `/web3-score`: collect scope/value data, run target score, recommend skip/narrow/full.
- `/web3-leads`: initialize, import, list, update, validate, and summarize `audit-leads.json` using the Lead Database Engine.
- `/web3-scan`: fingerprint repo, map contract surface, run safe build/tests/scanners, output leads only.
- `/web3-xray`: generate pre-audit x-ray artifacts: entry-points, invariants, architecture, docs/spec assumptions, tests, and git-risk signals.
- `/web3-index`: build `x-ray/code-index.json` with contracts, storage, functions, modifiers, callgraph edges, value movement, and risk signals.
- `/web3-hunt`: pick the top 3 crown-jewel components, run the finding playbook exploit loops, rank leads by PoC feasibility and impact, then build a PoC for the best `PROVE` lead.
- `/web3-hypothesize`: generate exploit sentences from attacker capabilities, invariants, boundaries, and cross-file assumptions; score each lead and choose `PROVE`, `CHAIN REQUIRED`, or `KILL`.
- `/web3-protocol`: classify target protocol type and apply the relevant protocol-specific playbook.
- `/web3-parallel-audit`: run the multi-lens audit swarm, deduplicate outputs, and validate only proof-backed leads.
- `/web3-ingest-scanners`: normalize scanner JSON outputs into proof-needed `LEAD` rows.
- `/web3-onchain`: use read-only RPC, Sourcify, explorers, proxy slots, owner/admin calls, balances, and expected deployment checks to verify live scope/state.
- `/web3-standards`: map a lead/finding to SWC, OWASP, EthTrust, SCSVS, OpenZeppelin, and remediation guidance.
- `/web3-language`: choose Solidity/Vyper/Rust module and tool plan for the target.
- `/web3-vyper`: run the Vyper/EVM language module.
- `/web3-rust`: run the Rust smart contract language module for Solana/Anchor, CosmWasm, ink!, or Stylus.
- `/web3-vuln-module`: apply a deep bug-class module such as reentrancy, math, access, oracle, signature, bridge, ERC4626, or AA/AI.
- `/web3-math`: targeted math precision lens.
- `/web3-access`: targeted access-control lens.
- `/web3-economics`: targeted economic security lens.
- `/web3-execution`: targeted execution trace lens.
- `/web3-periphery`: targeted helper/library/periphery lens.
- `/web3-first-principles`: targeted assumption-breaking lens.
- `/web3-vectors`: classify known attack vectors into skip/drop/investigate/prove/kill and investigate the top relevant ones.
- `/web3-eval`: run the hunter against the bundled intentionally vulnerable eval fixtures and compare expected bug shape vs found lead/PoC.
- `/web3-siblings`: build modifier matrix and identify inconsistent sibling guards.
- `/web3-assumptions`: create assumption ledger across files and state invariants.
- `/web3-invariant`: design Foundry/Echidna/Medusa invariants for accounting, shares, roles, signatures, oracle, or bridge logic.
- `/web3-poc-patterns`: choose the closest PoC pattern from `POC_PATTERN_LIBRARY.md` and adapt assertions to the lead.
- `/web3-foundry-poc`: generate a Foundry local/fork PoC scaffold from Lead DB, Code Index, and on-chain artifacts; scaffold must be manually completed before PoC `PASS`.
- `/web3-harness`: choose or draft adversarial test harness contracts needed to prove/kill the lead.
- `/web3-casebook`: compare a lead to known paid-bug shapes and rejected weak variants.
- `/web3-mine-reports`: mine public audit reports for similar protocol-type findings and convert them into hypotheses for the current target.
- `/web3-ai-review`: map AI read/call/sign/submit boundaries and produce exploit chains only where harmful capability exists.
- `/web3-diff-audit`: audit recent commits/upgrades for security regressions and changed assumptions.
- `/web3-poc`: write or generate a minimal exploit/control test for a specific `PROVE` lead, then run the narrow Foundry command and update Lead DB only after assertions pass.
- `/web3-validate`: run the strict 7-question gate and mark `REPORT`, `CHAIN REQUIRED`, or `KILL`.
- `/web3-report`: draft impact-first report only after validation passes.

## Final Discipline

Strong bug hunters kill most leads. A weak finding wastes time and increases N/A rate. Prefer one executable, in-scope, high-impact PoC over ten speculative issues.
