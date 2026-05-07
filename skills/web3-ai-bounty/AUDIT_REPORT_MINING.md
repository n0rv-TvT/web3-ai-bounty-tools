# Audit Report Mining Workflow

Purpose: learn from public audit reports before hunting a similar protocol. Public reports are a map of paid bug shapes and protocol-specific failure modes. They are not proof that the current target is vulnerable.

Good sources include public audit repositories such as Pashov Audit Group's `pashov/audits`, Code4rena/Sherlock/Cantina reports, Immunefi disclosures, and protocol postmortems. See `REPORT_MINING_SOURCES.md` for source links and query patterns.

## When To Use

Use `/web3-mine-reports` when:

- the target protocol type is known
- similar public audits exist
- you are stuck generating good hypotheses
- the target is a fork or close design relative
- the protocol has complex accounting/oracle/bridge/lending logic

## Mining Targets By Protocol Type

```text
Lending: Aave, Compound forks, Euler, Blueberry, Hyperlend, Radiant
DEX/AMM: Uniswap, Sushi, Curve/StableSwap, Bunni, Solidly, TWAMM systems
Stablecoin/RWA: Ethena, Resolv, Falcon, Dinari, DYAD, Open Dollar
Vault/Yield: Euler Earn, Yearn-like vaults, StakeDAO, Cove, GammaSwap
Bridge/Cross-chain: LayerZero/OFT, BOB bridge, Zipper, Tanssi
Liquid staking/restaking: Karak, Kinetiq, Rivus, stHYPE, Elytra
Account abstraction: Clave, Biconomy, Klaster, Mass
Perps/options: Gains, Reya, Ostium, Spectra, Napier
```

## Extraction Template

For each relevant report finding, extract:

```text
Report:
Protocol type:
Finding title:
Severity:
Bug class:
Affected component:
Root cause:
Minimal vulnerable pattern:
Exploit preconditions:
Exploit steps:
Accepted impact:
Fix pattern:
Weak variants likely rejected:
Current-target hypothesis:
Current-target files/functions to inspect:
```

## Translation Rule

Never copy a historical finding as-is. Translate it into a current-target hypothesis:

```text
Historical root cause: reward rate changed without settling accumulator.
Target hypothesis: If <Target>.setRewardRate() writes rewardRate without first updating rewardPerToken, then admin/keeper/user timing may overpay/underpay stakers.
Files to inspect: Rewards.sol::setRewardRate, notifyRewardAmount, stake, claim.
PoC target: victim reward loss equals attacker/admin-favored overpayment.
```

## Report Mining Loops

### Root-Cause Clustering

Group findings by root cause, not title:

- missing accumulator settlement
- stale oracle/price normalization
- share inflation/rounding
- missing domain separation
- state machine disagreement
- permissionless trigger value shift
- callback before consumed flag
- emergency path cleanup skip

Then ask: where does current target have the same root cause shape?

### Fix Pattern Inversion

Look at recommended fixes and search for missing equivalents:

```text
Fix says: updateReward before changing rewardRate.
Search target: every setter for rate/emission/cap that does not checkpoint first.
```

### Weak Variant Filter

For each historical bug, note what would make it N/A:

- admin-only and admin trust excluded
- documented delay/retry/recovery path
- loss is dust
- no normal attacker timing control
- malicious token out of scope
- MEV/frontrunning excluded

Use this to avoid N/A submissions.

## Output Format

```text
Mined Pattern MP-01: <root cause>
Source reports:
Current target match:
Files/functions to inspect:
Exploit sentence:
Expected impact:
Status: LEAD | PROVE | CHAIN_REQUIRED | NEEDS_CONTEXT | NEEDS_SCOPE_CONFIRMATION | NA_RISK | KILL
Next check:
```

## Casebook Update

When a mined pattern produces a real PoC or strong killed lesson, update `REAL_BUG_CASEBOOK.md` locally with:

- paid shape
- root cause
- minimal vulnerable pattern
- PoC assertion
- accepted/rejected distinction

Do not include confidential report content or private client data.
