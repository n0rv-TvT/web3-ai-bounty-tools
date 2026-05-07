# Web3 Hunter Evaluation Fixtures

Purpose: tiny vulnerable protocols for testing whether the hunter can produce real exploit hypotheses and Foundry PoCs. These are intentionally vulnerable and simplified.

Use them by copying one fixture into a Foundry project or by importing the contracts into a local test workspace.

Fixtures:

- `vault_inflation`: ERC4626-style first-depositor donation inflation.
- `signature_replay`: same signature drains escrow twice due to missing nonce/domain.
- `reward_desync`: late staker captures prior rewards because funding is not checkpointed.
- `bridge_double_finalize`: bridge finalize marks consumed after receiver callback.
- `proxy_reinit`: initialization can be called again to take ownership.
- `oracle_bad_debt`: public mutable spot oracle lets borrower create bad debt.

Expected hunter behavior:

1. Detect the vulnerable entry point.
2. Write an exploit sentence.
3. Pick a PoC pattern.
4. Produce a passing test with exact assertions.
5. Validate impact and reject weak variants.
