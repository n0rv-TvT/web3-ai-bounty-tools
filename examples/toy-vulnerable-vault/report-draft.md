# Report Draft

## Title

Toy vault credits shares from requested deposit amount instead of received assets

## Summary

In the synthetic example, the vault's share accounting can diverge from actual assets when a fee-on-transfer token is used.

## Impact

The local PoC would demonstrate unbacked shares in the toy vault. This is not a real bounty report and does not reference a real target.

## Reproduction

Run the local Foundry test described in `poc-plan.md`.

## Remediation

Credit shares based on the actual token balance delta or reject unsupported token behavior.
