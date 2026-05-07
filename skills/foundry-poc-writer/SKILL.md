# foundry-poc-writer

## Description

Turn a validated Web3 exploit hypothesis into a minimal Foundry exploit test and, when practical, a control test.

## When to use

- A code path looks reachable.
- The impact claim can be asserted locally.
- You need a minimal test that proves or kills the finding.

## Inputs expected

- Hypothesis statement.
- Affected contracts/functions.
- Setup requirements.
- Attacker/victim roles.
- Expected invariant break or impact.
- Existing test framework details.

## Output format

```text
## PoC plan
## Test setup
## Exploit steps
## Assertions
## Control test
## Foundry command
## Kill conditions
```

## Safety rules

- Prefer local tests over fork tests when possible.
- Do not use real private keys, seed phrases, or user funds.
- Do not broadcast transactions.
- Keep PoCs minimal and deterministic.
- Include assertions for concrete impact or state change.

## Example prompt

```text
Use the foundry-poc-writer skill to turn this hypothesis into an exploit test and a control test.
```
