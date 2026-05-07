# Security Policy

## Reporting a vulnerability

Do not open a public issue for vulnerabilities in this repository or for sensitive material accidentally committed here.

If you find a problem, contact the repository owner through GitHub profile contact options or open a minimal public issue that does not include secrets or exploit details.

Include, when safe:

- affected file or workflow
- description of the issue
- reproduction steps that do not include secrets
- potential impact
- suggested mitigation

## Sensitive data policy

This repository should never contain:

- private keys
- seed phrases
- wallet files
- `.env` files
- RPC URLs
- API tokens
- session cookies
- private platform messages
- real user data
- unsanitized target reports
- raw exploit logs

If sensitive data is found in history, rotate affected credentials immediately and remove the material from git history before continuing public use.
