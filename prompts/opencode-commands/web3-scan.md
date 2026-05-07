---
description: Run a Web3 baseline scan and summarize high-signal leads
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first. Use the `web3_audit` MCP if available.

Target: `$ARGUMENTS`

If no target is supplied, use the current repository.

Run this workflow:

1. Call Web3 tool status.
2. Fingerprint the project.
3. Build the contract surface map.
4. Run pattern scans for `accounting`, `access-control`, `oracle`, `erc4626`, `reentrancy`, `signature`, `proxy`, and `ai-agent` as applicable.
5. Run safe baseline tools when the repo supports them: `forge build`, `forge test`, `slither`, `aderyn`, `solhint`, and `semgrep`.
6. Summarize only high-signal leads with file/function references.
7. For each lead, state the missing proof needed before report writing.

Do not report scanner output as a finding. Convert promising leads into `/web3-poc` work.
