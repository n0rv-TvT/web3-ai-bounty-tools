# Public Audit Report Mining Sources

Purpose: source list for `/web3-mine-reports`. Use public reports to learn protocol-specific bug shapes, not to claim a current target is vulnerable.

## High-Value Public Sources

- Pashov Audit Group public audits: `https://github.com/pashov/audits`
- Code4rena reports: `https://code4rena.com/reports`
- Sherlock contests: `https://audits.sherlock.xyz/contests`
- Cantina competitions and reports: `https://cantina.xyz/competitions`
- Trail of Bits publications: `https://github.com/trailofbits/publications`
- OpenZeppelin audit reports: `https://www.openzeppelin.com/security-audits`
- Spearbit / Cantina reports: `https://github.com/spearbit/portfolio`
- Zellic reports: `https://reports.zellic.io/`
- Immunefi disclosed reports and postmortems: `https://immunefi.com/blog/`
- Rekt / incident writeups: `https://rekt.news/`

## Query Patterns

Use protocol type + root cause words:

```text
"ERC4626" "inflation" "audit report"
"rewardPerToken" "audit report" "stale"
"bridge" "finalize" "refund" "audit report"
"Chainlink" "stale" "bad debt" "audit report"
"signature replay" "nonce" "audit report" "Solidity"
"UUPS" "initialize" "audit report"
"paymaster" "validateUserOp" "audit report"
```

## Extraction Rule

Extract root cause, accepted impact, and fix pattern. Then translate into a target-specific hypothesis. Never report historical text as if it applies to the current target.
