---
description: Run Rust-based smart contract audit module
agent: web3-bounty-auditor
---

Load the `web3-ai-bounty` skill first and follow the Rust sections of `LANGUAGE_MODULES.md`.

Target:

`$ARGUMENTS`

Classify ecosystem: Solana/Anchor, CosmWasm, ink!, or Arbitrum Stylus.

Focus on signer/owner/account checks, PDA seeds, CPI privilege confusion, account reinitialization, unchecked remaining accounts, token account validation, close-account bugs, reply/state-machine mismatches, storage migrations, and arithmetic precision.

Return tool plan, high-risk constructs, and `PROVE`/`CHAIN REQUIRED`/`KILL` leads.
