#!/usr/bin/env python3
"""Link source facts to precise, PoC-oriented attack stories.

The linker consumes frozen detector artifacts only. It is a general repair step:
it does not read reports, expected findings, protocol names, or contest-specific
labels.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT, case_ids_for_split
from repair_to_poc_candidate_selection import candidate_id_for, find_hypothesis_for_candidate


GENERIC_ASSET = "protocol-controlled assets or security-sensitive state; exact asset requires validation"


def source_reasons(h: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    for ev in h.get("external_evidence") or []:
        reasons.extend(str(r) for r in ev.get("reasons") or [])
    return list(dict.fromkeys(reasons))


def root_cause_from_facts(h: dict[str, Any]) -> str:
    bug = str(h.get("bug_class") or "").lower()
    reasons = " ".join(source_reasons(h)).lower()
    fn = h.get("function") or "the entrypoint"
    if "signature" in bug or "signature" in reasons or "permit" in reasons:
        return f"authorization data around {fn} may lack nonce/domain/action binding or may be reusable across contexts"
    if "oracle" in bug or "oracle" in reasons or "price" in reasons or "snapshot" in reasons:
        return f"oracle or snapshot state read by {fn} may be stale, corruptible, or insufficiently domain-separated"
    if "access" in bug or "unguarded_sensitive_entrypoint" in reasons:
        return f"{fn} is a sensitive state-changing entrypoint whose caller assumptions need role, ownership, or sibling-guard validation"
    if "accounting" in bug or "accounting_signal" in reasons or "rounding" in bug:
        return f"recorded accounting around {fn} may diverge from actual balances, shares, or lifecycle limits"
    if "external_call" in reasons or "token_transfer" in reasons:
        return f"{fn} moves value or calls an external dependency before all cross-file assumptions are proven"
    return f"{fn} has source risk signals that need manual source trace before PoC work"


def asset_from_facts(h: dict[str, Any]) -> str:
    current = str(h.get("affected_asset") or "")
    if current and "requires validation" not in current.lower() and current != GENERIC_ASSET:
        return current
    text = " ".join([str(h.get("bug_class") or ""), str(h.get("function") or ""), " ".join(source_reasons(h))]).lower()
    contract = h.get("contract") or "target contract"
    if any(t in text for t in ["oracle", "price", "snapshot", "twap"]):
        return f"{contract} price/oracle outputs and dependent accounting"
    if any(t in text for t in ["signature", "session", "permit", "nonce"]):
        return f"authorized actions and funds controlled through {contract}"
    if any(t in text for t in ["access", "role", "unguarded", "permission", "delegate"]):
        return f"{contract} permissions, delegated state, and associated user balances or rewards"
    if any(t in text for t in ["accounting", "deposit", "withdraw", "supply", "redeem", "claim", "reward"]):
        return f"{contract} accounting balances, reserves, shares, or rewards"
    if any(t in text for t in ["transfer", "token", "native_asset"]):
        return f"tokens or native assets moved by {contract}"
    return f"security-sensitive state controlled by {contract}"


def exploit_path_from_facts(h: dict[str, Any], root_cause: str, asset: str) -> list[str]:
    contract = h.get("contract") or "target contract"
    fn = h.get("function") or "target function"
    return [
        f"establish the normal preconditions for {contract}.{fn}",
        f"execute the boundary condition suggested by source facts: {root_cause}",
        f"assert the resulting state or balance delta for {asset}",
    ]


def link_hypothesis(h: dict[str, Any]) -> dict[str, Any]:
    exact = bool(h.get("file_path") and h.get("contract") and h.get("function"))
    root = root_cause_from_facts(h)
    asset = asset_from_facts(h)
    path = exploit_path_from_facts(h, root, asset) if exact else []
    return {
        "hypothesis_id": h.get("id") or h.get("lead_id"),
        "case_id": h.get("case_id"),
        "file_path": h.get("file_path") or h.get("file"),
        "contract": h.get("contract"),
        "function": h.get("function"),
        "bug_class": h.get("bug_class"),
        "source_reasons": source_reasons(h),
        "exact_location": exact,
        "root_cause": root if exact else "missing exact file/contract/function prevents root-cause linking",
        "affected_asset": asset if exact else "unknown until exact location is available",
        "exploit_path": path,
        "link_status": "LINKED" if exact and path else "BLOCKED_MISSING_LOCATION",
        "report_ready": False,
        "counts_as_finding": False,
    }


def reconstruct_candidate_source_facts(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation", candidate: str = "") -> dict[str, Any]:
    selected, hypothesis = find_hypothesis_for_candidate(root, split, candidate)
    if not hypothesis:
        result = {
            "status": "REPAIR_INCONCLUSIVE",
            "split": split,
            "candidate": candidate,
            "reason": "selected repair candidate could not be resolved to a frozen hypothesis",
            "answer_key_access": False,
            "writeup_access": False,
            "network_used": False,
            "secrets_accessed": False,
            "broadcasts_used": False,
            "counts_toward_readiness": False,
        }
    else:
        story = link_hypothesis(hypothesis)
        case_id = str(hypothesis.get("case_id") or (selected or {}).get("case_id") or "")
        hypothesis_id = str(story.get("hypothesis_id") or hypothesis.get("id") or hypothesis.get("lead_id") or "")
        candidate_id = str((selected or {}).get("candidate_id") or candidate_id_for(case_id, hypothesis_id))
        reconstruction = {
            "candidate_id": candidate_id,
            "hypothesis_id": hypothesis_id,
            "case_id": case_id,
            "file_path": story.get("file_path"),
            "contract": story.get("contract"),
            "function": story.get("function"),
            "bug_class": story.get("bug_class"),
            "code_path": hypothesis.get("code_path") or [],
            "source_reasons": story.get("source_reasons") or [],
            "root_cause": story.get("root_cause"),
            "affected_asset": story.get("affected_asset"),
            "attacker_capability": hypothesis.get("attacker_capabilities") or hypothesis.get("attacker_capability"),
            "exploit_path": story.get("exploit_path") or [],
            "link_status": story.get("link_status"),
            "frozen_artifacts_only": True,
            "source_code_read": False,
            "report_ready": False,
            "counts_as_finding": False,
            "counts_toward_readiness": False,
        }
        result = {
            "status": "PASS" if story.get("link_status") == "LINKED" else "REPAIR_BLOCKED_MISSING_EXPLOIT_SEQUENCE",
            "split": split,
            "candidate_id": candidate_id,
            "hypothesis_id": hypothesis_id,
            "selection": selected or {},
            "source_fact_reconstruction": reconstruction,
            "story": story,
            "answer_key_access": False,
            "writeup_access": False,
            "network_used": False,
            "secrets_accessed": False,
            "broadcasts_used": False,
            "counts_toward_readiness": False,
        }
    out = root / "scoring" / "repair_to_poc_source_fact_reconstruction.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    return result


def run_split(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation") -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for case_id in case_ids_for_split(root, split):
        path = root / "generated_reports" / f"{case_id}_hypotheses.json"
        if not path.exists():
            continue
        payload = json.loads(path.read_text(errors="replace"))
        rows.extend(link_hypothesis(dict(h, case_id=case_id)) for h in payload.get("hypotheses", []))
    result = {
        "status": "PASS" if rows else "BLOCKED",
        "split": split,
        "linked_count": sum(1 for r in rows if r["link_status"] == "LINKED"),
        "blocked_count": sum(1 for r in rows if r["link_status"] != "LINKED"),
        "stories": rows,
        "answer_key_access": False,
        "writeup_access": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "counts_toward_readiness": False,
    }
    out = root / "scoring" / "source_fact_attack_story_links.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Link frozen source facts to attack stories")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="fresh-confirmation")
    p.add_argument("--frozen-only", action="store_true")
    p.add_argument("--candidate", default="", help="repair candidate id or hypothesis id to reconstruct")
    args = p.parse_args(argv)
    result = reconstruct_candidate_source_facts(Path(args.root), split=args.split, candidate=args.candidate) if args.candidate else run_split(Path(args.root), split=args.split)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] in {"PASS", "BLOCKED", "REPAIR_BLOCKED_MISSING_EXPLOIT_SEQUENCE", "REPAIR_INCONCLUSIVE"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
