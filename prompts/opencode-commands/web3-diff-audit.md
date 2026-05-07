---
description: Audit recent Solidity/Web3 changes for security regressions
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Audit the recent diff or specified range:

`$ARGUMENTS`

If no range is supplied, inspect unstaged, staged, and recent committed changes.

Focus on:

- New or changed external/public functions.
- Modifier, role, pause, epoch, and initializer changes.
- Accounting variable updates and ordering.
- Oracle source, staleness, confidence, or TWAP changes.
- Token transfer and external call ordering.
- Signature domain, nonce, deadline, and chain binding changes.
- AI agent tool permission, prompt, signing, and transaction submission changes.

Return findings first, ordered by severity, with file/function references. If no findings, state residual risk and missing tests.
