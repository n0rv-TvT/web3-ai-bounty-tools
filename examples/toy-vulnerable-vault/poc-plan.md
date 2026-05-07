# PoC Plan

## Setup

- Deploy toy vault.
- Deploy toy fee-on-transfer token.
- Give attacker tokens and approval.

## Exploit test

1. Record vault assets and attacker shares.
2. Attacker deposits an amount where the token transfers less than requested.
3. Assert attacker shares are credited for the requested amount while vault assets increased by less.

## Control test

1. Repeat deposit with a normal token.
2. Assert shares and assets remain consistent.

## Expected command

```bash
forge test --match-test test_exploit_feeOnTransferShareOvercredit -vv
```
