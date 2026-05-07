---
description: Find sibling function and modifier inconsistencies in Solidity code
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Use the `web3_audit` MCP sibling modifier report and modifier matrix against:

`$ARGUMENTS`

If no target is supplied, use the current repository.

Focus on sibling families:

- `deposit`, `mint`, `withdraw`, `redeem`
- `stake`, `unstake`, `claim`, `harvest`, `compound`
- `vote`, `poke`, `reset`, `attach`, `detach`
- `create`, `update`, `cancel`, `fill`
- `initialize`, `upgradeTo`, `setImplementation`
- `set*` and `update*` admin functions

Return modifier mismatches first. For each mismatch, explain whether it likely matters and what PoC would prove impact.
