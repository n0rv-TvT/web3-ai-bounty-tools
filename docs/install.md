# Install and Use

Clone the repo:

```bash
git clone https://github.com/n0rv-TvT/web3-ai-bounty-tools.git
cd web3-ai-bounty-tools
```

Use the markdown skills/prompts with your coding agent of choice.

Example prompts:

```text
Install https://github.com/n0rv-TvT/web3-ai-bounty-tools and use the web3-ai-bounty skill on this authorized repo.
```

```text
Use the poc-first-validator skill to decide whether this lead should be proven, killed, or report-ready.
```

```text
Use the foundry-poc-writer skill to create a minimal exploit/control test plan.
```

## Local script usage

Most reusable scripts are under:

```text
skills/web3-ai-bounty/scripts/
```

Examples:

```bash
python3 skills/web3-ai-bounty/scripts/safety_guard.py --self-test
python3 skills/web3-ai-bounty/scripts/readiness_policy.py --self-test
python3 skills/web3-ai-bounty/scripts/report_linter.py --help
```

Some scripts expect local artifacts or schemas from the same skill directory. Read the script help and use toy examples before using them on real authorized targets.
