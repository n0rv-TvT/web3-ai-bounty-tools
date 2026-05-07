# Foundry Fork PoC Generator

Production component 5 of the Web3 audit engine.

## Purpose

The Foundry PoC Generator turns a validated `PROVE`-stage lead into a local or fork-test scaffold with the correct actors, target metadata, bug-class pattern, control/exploit test shape, harness snippets, and Lead DB update commands.

It does **not** pretend to exploit automatically. Generated exploit tests intentionally fail until the auditor fills the concrete exploit sequence and assertions. This prevents empty scaffolds from being mistaken for proof.

## Files

- CLI: `scripts/foundry_poc_generator.py`
- JSON Schema: `schemas/foundry_poc_plan.schema.json`
- Example plan: `examples/foundry_poc_plan.example.json`
- Example scaffold: `examples/L0001VaultInflationPoC.example.t.sol`
- Human template: `FOUNDRY_POC_TEMPLATE.md`
- Pattern reference: `POC_PATTERN_LIBRARY.md`
- Harness reference: `ADVERSARIAL_TEST_HARNESS.md`

## Inputs

The generator can consume:

- Lead DB: `audit-leads.json` + `--lead-id`
- On-chain verification report: `onchain.json`
- Code Index artifact: `x-ray/code-index.json`
- Manual overrides: bug class, target address, implementation, asset, chain ID, block, RPC env, target contract/function

Recommended flow:

```text
Lead DB PROVE lead + Code Index + On-chain verification -> Foundry scaffold -> auditor fills exploit/control -> forge test passes -> Lead DB add-poc PASS
```

## Commands

Generate from Lead DB only:

```bash
python3 <skill-dir>/scripts/foundry_poc_generator.py \
  --project-root . \
  --lead-db audit-leads.json \
  --lead-id L-0001 \
  --out test/L0001Exploit.t.sol \
  --metadata test/L0001Exploit.plan.json
```

Generate from Lead DB + on-chain verification + code index:

```bash
python3 <skill-dir>/scripts/foundry_poc_generator.py \
  --project-root . \
  --lead-db audit-leads.json \
  --lead-id L-0001 \
  --onchain onchain/1-target.json \
  --code-index x-ray/code-index.json \
  --out test/L0001Exploit.t.sol \
  --metadata test/L0001Exploit.plan.json
```

Generate manually for a deployed fork target:

```bash
python3 <skill-dir>/scripts/foundry_poc_generator.py \
  --project-root . \
  --bug-class signature-replay \
  --target-address <target> \
  --chain-id 1 \
  --block 20000000 \
  --rpc-env MAINNET_RPC_URL \
  --asset <token> \
  --out test/SignatureReplayPoC.t.sol
```

Run after filling TODOs:

```bash
forge test --match-path test/L0001Exploit.t.sol --match-test test_exploit -vvvv
```

Validate the plan:

```bash
python3 - <<'PY'
import json, jsonschema
schema=json.load(open('<skill-dir>/schemas/foundry_poc_plan.schema.json'))
data=json.load(open('test/L0001Exploit.plan.json'))
jsonschema.Draft202012Validator(schema).validate(data)
print('Foundry PoC plan schema passed')
PY
```

## Lead DB Integration

After generation, record the planned scaffold if desired:

```bash
python3 <skill-dir>/scripts/lead_db.py add-poc audit-leads.json L-0001 \
  --path test/L0001Exploit.t.sol \
  --command "forge test --match-path test/L0001Exploit.t.sol --match-test test_exploit -vvvv" \
  --status PLANNED \
  --summary "generated scaffold; exploit assertions still TODO"
```

Only after the exploit test passes and asserts impact:

```bash
python3 <skill-dir>/scripts/lead_db.py add-poc audit-leads.json L-0001 \
  --path test/L0001Exploit.t.sol \
  --command "forge test --match-path test/L0001Exploit.t.sol --match-test test_exploit -vvvv" \
  --status PASS \
  --summary "PoC passes and asserts concrete impact"
```

`REPORT_READY` still requires the strict validation gate after PoC `PASS`.

## Pattern Mapping

The generator maps lead bug classes into PoC patterns:

- `erc4626-inflation`: first depositor donation/share inflation
- `reentrancy`: callback/external-call-before-state ordering
- `signature-replay`: nonce/domain/action replay
- `oracle-bad-debt`: manipulated/stale price economic path
- `access-control`: sibling guard bypass
- `proxy-initialization`: initialize/reinitialize takeover
- `bridge-double-finalize`: retry/cancel/finalize double release
- `accounting-desync`: stale rewards/loss/checkpoint state
- `nonstandard-token`: unchecked transfer/FOT/rebasing token accounting
- `generic`: invariant-breaking scaffold

Use `--pattern <id>` to override automatic mapping.

## Harness Generation

Default `--include-harness auto` includes only the harnesses relevant to the selected pattern:

- `ReentrantHarness`
- `MutableOracleHarness`
- `SignatureReplayHelper`
- `FalseReturnERC20Harness`
- `MaliciousBridgeReceiverHarness`

Use:

```bash
--include-harness none
--include-harness all
```

Harnesses live inside the generated test file. Production contracts are never modified.

## Generated Test Discipline

Every scaffold includes:

- named actors: `alice`, `victim`, `attacker`, `keeper`
- fork setup using `vm.createFork(vm.envString(RPC_ENV), FORK_BLOCK)` when a deployed target exists
- target/implementation/asset constants
- control test
- exploit test
- exact TODO sections for setup, attack, proof assertions
- failure guards (`fail(...)`) so incomplete tests cannot pass accidentally

Before marking PoC `PASS`, replace the failure guards with exact assertions proving one of:

- attacker profit / stolen funds
- victim or protocol loss
- bad debt
- frozen funds with program-required duration
- unauthorized privileged action
- sensitive data exposure
- unsafe signing/tool execution

## Safety Rules

- Generated tests are local/fork-only.
- No private keys, seed phrases, or real user funds.
- No transaction broadcasts.
- No production contract edits.
- No report from scaffold alone.
- Run the narrow test first, then broader tests if needed.
