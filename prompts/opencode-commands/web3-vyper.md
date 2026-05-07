---
description: Run Vyper-specific Web3 audit module
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow the Vyper section of `LANGUAGE_MODULES.md`.

Target:

`$ARGUMENTS`

Focus on `@external`/`@internal` visibility, `@nonreentrant` lock coverage, `raw_call`, decimal math, storage layout, external-call ordering, sentinel addresses, and ERC20 return handling.

Return `PROVE`, `CHAIN REQUIRED`, and `KILL` leads with exact PoC/test recommendations.
