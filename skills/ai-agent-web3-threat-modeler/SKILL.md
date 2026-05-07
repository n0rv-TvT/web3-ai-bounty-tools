# ai-agent-web3-threat-modeler

## Description

Threat-model AI-enabled Web3 systems where untrusted content may influence signing, transaction generation, tool calls, memory, or sensitive data access.

## When to use

- Reviewing AI wallets, trading agents, chatbots, portfolio agents, or transaction builders.
- Testing prompt injection only when it reaches a harmful capability.
- Mapping AI tool permissions and data boundaries.

## Inputs expected

- What the AI can read.
- What tools the AI can call.
- Whether it can sign, submit transactions, change settings, or access user data.
- Sources of untrusted content.
- Confirmation/approval model.

## Output format

```text
## AI read boundaries
## AI tool/action boundaries
## Untrusted input sources
## Harmful capability chains
## High-risk test cases
## Findings to prove
## Findings to kill as prompt-injection-only
```

## Safety rules

- Prompt injection alone is not enough; connect it to signing, transaction submission, data leakage, privileged tool use, or security-sensitive state change.
- Do not use real keys, funds, or user data.
- Do not exfiltrate secrets.
- Test only authorized systems or local labs.

## Example prompt

```text
Use the ai-agent-web3-threat-modeler skill to map whether untrusted token metadata can cause unsafe signing or tool calls.
```
