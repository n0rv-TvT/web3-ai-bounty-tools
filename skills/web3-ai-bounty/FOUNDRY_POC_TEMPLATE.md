# Foundry PoC Template

Use this shape for bounty-grade tests. Keep one control test and one exploit test.

For a generated scaffold, prefer:

```bash
python3 <skill-dir>/scripts/foundry_poc_generator.py --lead-db audit-leads.json --lead-id L-0001 --onchain onchain.json --code-index x-ray/code-index.json --out test/L0001Exploit.t.sol
```

The generator intentionally inserts failing TODO guards. Replace them with concrete exploit steps and assertions before marking PoC `PASS`.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

contract ExploitTest is Test {
    address internal alice = address(0xA11CE);
    address internal victim = address(0xBEEF);
    address internal attacker = address(0xA77A);
    address internal keeper = address(0xA11);

    function setUp() public {
        // Setup: deploy contracts or create a fork.
        // Example fork pattern:
        // uint256 fork = vm.createFork(vm.envString("MAINNET_RPC_URL"), 20_000_000);
        // vm.selectFork(fork);

        // Setup actors, balances, roles, approvals, and baseline state.
        vm.label(alice, "alice");
        vm.label(victim, "victim");
        vm.label(attacker, "attacker");
        vm.label(keeper, "keeper");
    }

    function test_control_honestPathWorks() public {
        // Setup honest state.

        // Execute the normal user flow.

        // Assert exact expected accounting/balances.
        // assertEq(actual, expected, "honest path accounting mismatch");
    }

    function test_exploit_attackerStealsVictimFunds() public {
        // Setup: victim has normal protocol position before attack.
        uint256 attackerBefore = 0; // token.balanceOf(attacker);
        uint256 victimBefore = 0; // token.balanceOf(victim);

        // Baseline: prove honest preconditions.
        // assertEq(vault.totalAssets(), expectedAssets, "baseline assets wrong");

        // Attack: execute the exploit step by step.
        vm.startPrank(attacker);
        // 1. First exploit action.
        // 2. Key invariant violation.
        // 3. Final withdrawal/profit action.
        vm.stopPrank();

        // Proof: prove both sides of impact.
        uint256 attackerAfter = 0; // token.balanceOf(attacker);
        uint256 victimAfter = 0; // token.balanceOf(victim);
        uint256 attackerGain = attackerAfter - attackerBefore;
        uint256 victimLoss = victimBefore - victimAfter;

        assertGt(attackerGain, 0, "attacker did not profit");
        assertEq(attackerGain, victimLoss, "attacker gain must equal victim loss");
    }
}
```

Run:

```bash
forge test --match-test test_exploit -vvvv
```
