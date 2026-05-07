#!/usr/bin/env python3
"""Read-only git risk summary for Web3 audits.

Scores current-branch files and commits using security-sensitive keywords. This
creates leads and priorities only; it does not prove vulnerabilities.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path


SECURITY_WORDS = {
    "fix", "bug", "audit", "security", "exploit", "vuln", "reentrancy", "oracle",
    "rounding", "precision", "nonce", "replay", "signature", "upgrade", "proxy",
    "initializer", "liquidation", "reward", "debt", "collateral", "bridge", "pause",
}

DANGEROUS_PATH_WORDS = {
    "vault", "strategy", "oracle", "bridge", "router", "market", "liquidat",
    "reward", "staking", "proxy", "upgrade", "signature", "permit", "govern",
    "paymaster", "wallet", "entrypoint", "settle", "withdraw", "redeem", "claim",
}


@dataclass
class RiskCommit:
    sha: str
    subject: str
    score: int
    files: list[str]


def git(args: list[str], cwd: Path) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=cwd, text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        return ""


def current_branch(repo: Path) -> str:
    return git(["rev-parse", "--abbrev-ref", "HEAD"], repo).strip() or "unknown"


def current_commit(repo: Path) -> str:
    return git(["rev-parse", "--short", "HEAD"], repo).strip() or "unknown"


def list_commits(repo: Path, limit: int) -> list[tuple[str, str]]:
    out = git(["log", f"-{limit}", "--pretty=format:%H%x00%s"], repo)
    commits = []
    for line in out.splitlines():
        if "\x00" in line:
            sha, subject = line.split("\x00", 1)
            commits.append((sha, subject))
    return commits


def changed_files(repo: Path, sha: str) -> list[str]:
    out = git(["show", "--name-only", "--pretty=format:", sha], repo)
    return [x for x in out.splitlines() if x.strip()]


def score_commit(subject: str, files: list[str]) -> int:
    s = subject.lower()
    score = sum(2 for w in SECURITY_WORDS if w in s)
    for f in files:
        lf = f.lower()
        if f.endswith(".sol"):
            score += 1
        if any(w in lf for w in DANGEROUS_PATH_WORDS):
            score += 2
        if any(seg in lf for seg in ("test", "mock", "script")):
            score -= 1
    return max(score, 0)


def churn(repo: Path, limit: int) -> Counter[str]:
    counts: Counter[str] = Counter()
    for sha, _ in list_commits(repo, limit):
        for f in changed_files(repo, sha):
            if f.endswith(".sol"):
                counts[f] += 1
    return counts


def main() -> int:
    ap = argparse.ArgumentParser(description="Summarize git risk signals")
    ap.add_argument("repo", nargs="?", default=".")
    ap.add_argument("--limit", type=int, default=80)
    ap.add_argument("--json", dest="json_path")
    args = ap.parse_args()
    repo = Path(args.repo).resolve()

    risks: list[RiskCommit] = []
    touched_by_file: defaultdict[str, list[str]] = defaultdict(list)
    for sha, subject in list_commits(repo, args.limit):
        files = changed_files(repo, sha)
        sc = score_commit(subject, files)
        if sc >= 4:
            risks.append(RiskCommit(sha=sha[:10], subject=subject, score=sc, files=files[:20]))
        for f in files:
            if f.endswith(".sol"):
                touched_by_file[f].append(sha[:10])

    hot = churn(repo, args.limit).most_common(20)
    dangerous_hot = [(f, n) for f, n in hot if any(w in f.lower() for w in DANGEROUS_PATH_WORDS)]
    data = {
        "branch": current_branch(repo),
        "head": current_commit(repo),
        "commit_limit": args.limit,
        "risk_commits": [asdict(r) for r in sorted(risks, key=lambda r: r.score, reverse=True)],
        "hot_files": hot,
        "dangerous_hot_files": dangerous_hot,
    }

    if args.json_path:
        Path(args.json_path).write_text(json.dumps(data, indent=2))

    print("# Git Risk Signals")
    print()
    print(f"Analyzed branch: `{data['branch']}` at `{data['head']}`")
    print(f"Commit window: last {args.limit} commits")
    print()
    print("## High-Risk Commits")
    if not risks:
        print("- No high-risk commit subjects/files detected in window.")
    for r in sorted(risks, key=lambda r: r.score, reverse=True)[:20]:
        print(f"- `{r.sha}` score={r.score}: {r.subject}")
        if r.files:
            print(f"  - files: {', '.join(r.files[:8])}")
    print()
    print("## Hot Solidity Files")
    for f, n in hot[:20]:
        marker = " ⚠️" if any(w in f.lower() for w in DANGEROUS_PATH_WORDS) else ""
        print(f"- {f}: {n} commits{marker}")
    print()
    print("Use these as hunting priorities only. Git history alone is not a vulnerability.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
