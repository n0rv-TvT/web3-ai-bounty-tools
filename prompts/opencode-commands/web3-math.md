---
description: Run Web3 math precision audit lens
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Run only the math precision lens on `$ARGUMENTS`.

Focus on rounding direction, decimal normalization, division-before-multiplication, downcasts, overflow intermediates, ERC4626 preview/execute mismatch, and zero-rounding.

Return `PROVE`, `CHAIN REQUIRED`, and `KILL` leads with concrete arithmetic. No numbers means no finding.
