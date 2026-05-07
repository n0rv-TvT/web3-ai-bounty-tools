---
description: Run Web3 first-principles assumption-breaking audit lens
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Run only the first-principles lens on `$ARGUMENTS`.

Ignore named bug classes. For every state-changing function, extract assumptions, violate them with attacker-controlled inputs/order/timing, and trace whether corrupted state creates concrete impact.

Return exploit sentences and proof targets. Kill assumptions that do not monetize or match accepted impact.
