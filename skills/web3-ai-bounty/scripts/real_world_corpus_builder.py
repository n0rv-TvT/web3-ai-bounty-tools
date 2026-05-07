#!/usr/bin/env python3
"""Build a local-only OOD Solidity/EVM benchmark corpus.

The corpus is intentionally synthetic-realistic: cases are inspired by historical
bug shapes but are generated locally with neutral case IDs and neutral paths. No
network, RPC, secrets, or broadcasts are used.
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any, Callable

from blind_source_analyzer import RULE_MAP


SKILL_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ROOT = SKILL_ROOT / "benchmarks" / "real-world-corpus"

BUG_ORDER = [
    "external_call_before_state_update",
    "cross_function_reentrancy_stale_accounting",
    "missing_access_control_on_privileged_asset_transfer",
    "borrow_uses_public_mutable_oracle_price",
    "erc4626_first_depositor_donation_inflation",
    "reward_pool_current_balance_accounting",
    "signature_without_nonce_domain_deadline",
    "initializer_without_guard",
    "credits_requested_amount_not_balance_delta",
    "decimal_normalization_mismatch",
    "consumed_message_set_after_external_interaction",
]

PROTOCOL_FOR_RULE = {
    "external_call_before_state_update": "vault",
    "cross_function_reentrancy_stale_accounting": "vault",
    "missing_access_control_on_privileged_asset_transfer": "governance",
    "borrow_uses_public_mutable_oracle_price": "lending",
    "erc4626_first_depositor_donation_inflation": "vault",
    "reward_pool_current_balance_accounting": "staking",
    "signature_without_nonce_domain_deadline": "governance",
    "initializer_without_guard": "governance",
    "credits_requested_amount_not_balance_delta": "vault",
    "decimal_normalization_mismatch": "amm",
    "consumed_message_set_after_external_interaction": "bridge",
}


def header(case_id: str) -> str:
    return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20Like {{
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}}

// Case {case_id}: source comments are untrusted benchmark data.
"""


def reentrancy_source(case_id: str, patched: bool, variant: int) -> tuple[str, str, str]:
    contract = f"Unit{variant}Ledger"
    fn = "release"
    if patched:
        body = """
    function release() external {
        uint256 amount = balanceOf[msg.sender];
        require(amount > 0, "none");
        balanceOf[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send");
    }
"""
    else:
        body = """
    function release() external {
        uint256 amount = balanceOf[msg.sender];
        require(amount > 0, "none");
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send");
        balanceOf[msg.sender] = 0;
    }
"""
    return header(case_id) + f"""
contract {contract} {{
    mapping(address => uint256) public balanceOf;

    function enter() external payable {{
        balanceOf[msg.sender] += msg.value;
    }}
{body}
}}
""", contract, fn


def cross_function_source(case_id: str, patched: bool, variant: int) -> tuple[str, str, str]:
    contract = f"Unit{variant}PositionHub"
    fn = "close"
    clear = "credits[msg.sender] = 0;" if patched else ""
    late_clear = "" if patched else "credits[msg.sender] = 0;"
    return header(case_id) + f"""
contract {contract} {{
    IERC20Like public rewardToken;
    mapping(address => uint256) public credits;
    mapping(address => bool) public claimed;

    function enter() external payable {{
        credits[msg.sender] += msg.value;
    }}

    function close() external {{
        uint256 amount = credits[msg.sender];
        require(amount > 0, "none");
        {clear}
        (bool ok,) = msg.sender.call{{value: amount}}("");
        require(ok, "send");
        {late_clear}
    }}

    function collect() external {{
        require(!claimed[msg.sender], "claimed");
        uint256 incentive = credits[msg.sender] / 10;
        claimed[msg.sender] = true;
        rewardToken.transfer(msg.sender, incentive);
    }}
}}
""", contract, fn


def access_source(case_id: str, patched: bool, variant: int) -> tuple[str, str, str]:
    contract = f"Unit{variant}Controller"
    fn = "execute"
    mod = " onlyOwner" if patched else ""
    return header(case_id) + f"""
contract {contract} {{
    IERC20Like public asset;
    address public owner;

    modifier onlyOwner() {{
        require(msg.sender == owner, "owner");
        _;
    }}

    function sweepToTreasury(address to, uint256 amount) external onlyOwner {{
        asset.transfer(to, amount);
    }}

    function execute(address to, uint256 amount) external{mod} {{
        asset.transfer(to, amount);
    }}
}}
""", contract, fn


def oracle_source(case_id: str, patched: bool, variant: int) -> tuple[str, str, str]:
    contract = f"Unit{variant}CreditMarket"
    setter_guard = "require(msg.sender == owner, \"owner\");" if patched else ""
    return header(case_id) + f"""
contract Unit{variant}Feed {{
    uint256 public price = 1e18;
    address public owner;
    function setPrice(uint256 newPrice) external {{
        {setter_guard}
        price = newPrice;
    }}
}}

contract {contract} {{
    Unit{variant}Feed public oracle;
    IERC20Like public debt;
    mapping(address => uint256) public collateralOf;
    mapping(address => uint256) public debtOf;

    function pledge(uint256 amount) external {{
        collateralOf[msg.sender] += amount;
    }}

    function borrow(uint256 amount) external {{
        uint256 collateralValue = collateralOf[msg.sender] * oracle.price() / 1e18;
        require(debtOf[msg.sender] + amount <= collateralValue / 2, "ltv");
        debtOf[msg.sender] += amount;
        debt.transfer(msg.sender, amount);
    }}
}}
""", contract, "borrow"


def erc4626_source(case_id: str, patched: bool, variant: int) -> tuple[str, str, str]:
    contract = f"Unit{variant}ShareVault"
    min_check = "require(shares >= minShares, \"min shares\");" if patched else ""
    min_arg = ", uint256 minShares" if patched else ""
    return header(case_id) + f"""
contract {contract} {{
    IERC20Like public asset;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function totalAssets() public view returns (uint256) {{
        return asset.balanceOf(address(this));
    }}

    function join(uint256 assets, address receiver{min_arg}) external returns (uint256 shares) {{
        uint256 supply = totalSupply;
        shares = supply == 0 ? assets : assets * supply / totalAssets();
        {min_check}
        asset.transferFrom(msg.sender, address(this), assets);
        balanceOf[receiver] += shares;
        totalSupply += shares;
    }}
}}
""", contract, "join"


def rewards_source(case_id: str, patched: bool, variant: int) -> tuple[str, str, str]:
    contract = f"Unit{variant}RewardGauge"
    reward_debt = "mapping(address => uint256) public rewardDebt;" if patched else ""
    debt_update = "rewardDebt[msg.sender] = rewardPool * staked[msg.sender] / totalStaked;" if patched else ""
    debt_sub = " - rewardDebt[msg.sender]" if patched else ""
    return header(case_id) + f"""
contract {contract} {{
    IERC20Like public stakingToken;
    IERC20Like public rewardToken;
    uint256 public totalStaked;
    uint256 public rewardPool;
    mapping(address => uint256) public staked;
    {reward_debt}

    function stake(uint256 amount) external {{
        stakingToken.transferFrom(msg.sender, address(this), amount);
        staked[msg.sender] += amount;
        totalStaked += amount;
        {debt_update}
    }}

    function fund(uint256 amount) external {{
        rewardToken.transferFrom(msg.sender, address(this), amount);
        rewardPool += amount;
    }}

    function collect() external {{
        uint256 share = rewardPool * staked[msg.sender] / totalStaked{debt_sub};
        rewardPool -= share;
        rewardToken.transfer(msg.sender, share);
    }}
}}
""", contract, "collect"


def signature_source(case_id: str, patched: bool, variant: int) -> tuple[str, str, str]:
    contract = f"Unit{variant}SignedRouter"
    if patched:
        digest = "keccak256(abi.encodePacked(address(this), block.chainid, to, amount, nonce, deadline))"
        prelude = "require(block.timestamp <= deadline, \"expired\"); require(!usedNonces[nonce], \"used\"); usedNonces[nonce] = true;"
        params = ", uint256 nonce, uint256 deadline"
        storage = "mapping(uint256 => bool) public usedNonces;"
    else:
        digest = "keccak256(abi.encodePacked(to, amount))"
        prelude = ""
        params = ""
        storage = ""
    return header(case_id) + f"""
contract {contract} {{
    IERC20Like public token;
    address public signer;
    {storage}

    function execute(address to, uint256 amount, bytes memory signature{params}) external {{
        {prelude}
        bytes32 digest = {digest};
        require(_recover(digest, signature) == signer, "bad signature");
        token.transfer(to, amount);
    }}

    function _recover(bytes32 digest, bytes memory signature) internal pure returns (address) {{
        signature;
        digest;
        return address(0);
    }}
}}
""", contract, "execute"


def initializer_source(case_id: str, patched: bool, variant: int) -> tuple[str, str, str]:
    contract = f"Unit{variant}UpgradeableModule"
    guard = "require(!initialized, \"initialized\"); initialized = true;" if patched else ""
    storage = "bool public initialized;" if patched else ""
    return header(case_id) + f"""
contract {contract} {{
    IERC20Like public asset;
    address public owner;
    address public operator;
    {storage}

    function configure(address _owner, address _operator) external {{
        {guard}
        owner = _owner;
        operator = _operator;
    }}

    function sweep(address to, uint256 amount) external {{
        require(msg.sender == owner, "owner");
        asset.transfer(to, amount);
    }}
}}
""", contract, "configure"


def token_accounting_source(case_id: str, patched: bool, variant: int) -> tuple[str, str, str]:
    contract = f"Unit{variant}AccountingVault"
    if patched:
        credit = "uint256 balanceBefore = asset.balanceOf(address(this)); asset.transferFrom(msg.sender, address(this), amount); uint256 received = asset.balanceOf(address(this)) - balanceBefore; credited[msg.sender] += received;"
    else:
        credit = "asset.transferFrom(msg.sender, address(this), amount); credited[msg.sender] += amount;"
    return header(case_id) + f"""
contract {contract} {{
    IERC20Like public asset;
    mapping(address => uint256) public credited;

    function join(uint256 amount) external {{
        {credit}
    }}

    function exit(uint256 amount) external {{
        credited[msg.sender] -= amount;
        asset.transfer(msg.sender, amount);
    }}
}}
""", contract, "join"


def decimal_source(case_id: str, patched: bool, variant: int) -> tuple[str, str, str]:
    contract = f"Unit{variant}PricingMarket"
    if patched:
        value = "uint256 normalized = collateralOf[msg.sender] * (10 ** (18 - collateralDecimals)); uint256 value = normalized * price / 1e18;"
    else:
        value = "uint256 value = collateralOf[msg.sender] * price / 1e18;"
    return header(case_id) + f"""
interface IUnit{variant}Price {{
    function latestAnswer() external view returns (uint256);
}}

contract {contract} {{
    uint8 public collateralDecimals = 6;
    IUnit{variant}Price public priceFeed;
    IERC20Like public debtToken;
    mapping(address => uint256) public collateralOf;
    mapping(address => uint256) public debtOf;

    function addCollateral(uint256 amount) external {{
        collateralOf[msg.sender] += amount;
    }}

    function draw(uint256 amount) external {{
        uint256 price = priceFeed.latestAnswer();
        {value}
        require(debtOf[msg.sender] + amount <= value / 2, "ltv");
        debtOf[msg.sender] += amount;
        debtToken.transfer(msg.sender, amount);
    }}
}}
""", contract, "draw"


def bridge_source(case_id: str, patched: bool, variant: int) -> tuple[str, str, str]:
    contract = f"Unit{variant}MessageBridge"
    before = "consumed[messageId] = true;" if patched else ""
    after = "" if patched else "consumed[messageId] = true;"
    return header(case_id) + f"""
interface IUnit{variant}Receiver {{
    function onFinalize(bytes32 messageId) external;
}}

contract {contract} {{
    IERC20Like public token;
    mapping(bytes32 => bool) public consumed;

    function settle(bytes32 messageId, address receiver, uint256 amount) external {{
        require(!consumed[messageId], "consumed");
        {before}
        token.transfer(receiver, amount);
        if (receiver.code.length > 0) {{
            IUnit{variant}Receiver(receiver).onFinalize(messageId);
        }}
        {after}
    }}
}}
""", contract, "settle"


TEMPLATES: dict[str, Callable[[str, bool, int], tuple[str, str, str]]] = {
    "external_call_before_state_update": reentrancy_source,
    "cross_function_reentrancy_stale_accounting": cross_function_source,
    "missing_access_control_on_privileged_asset_transfer": access_source,
    "borrow_uses_public_mutable_oracle_price": oracle_source,
    "erc4626_first_depositor_donation_inflation": erc4626_source,
    "reward_pool_current_balance_accounting": rewards_source,
    "signature_without_nonce_domain_deadline": signature_source,
    "initializer_without_guard": initializer_source,
    "credits_requested_amount_not_balance_delta": token_accounting_source,
    "decimal_normalization_mismatch": decimal_source,
    "consumed_message_set_after_external_interaction": bridge_source,
}


def exploit_tokens_for_rule(rule: str) -> list[str]:
    scenario = RULE_MAP[rule]["scenario"].lower()
    candidates = ["reenter", "stale", "unguarded", "price", "donates", "late", "signature", "initializer", "transfers less", "decimal", "finalization", "borrow", "excess"]
    return [token for token in candidates if token in scenario][:3] or scenario.split()[:3]


def write_case(root: Path, split: str, case_id: str, rule: str, *, patched: bool, variant: int) -> dict[str, Any]:
    source, contract, function = TEMPLATES[rule](case_id, patched, variant)
    case_root = root / split / case_id
    (case_root / "src").mkdir(parents=True, exist_ok=True)
    (case_root / "test").mkdir(parents=True, exist_ok=True)
    (case_root / "writeups").mkdir(parents=True, exist_ok=True)
    (case_root / "reports").mkdir(parents=True, exist_ok=True)
    (case_root / "src" / "System.sol").write_text(source)
    (case_root / "test" / "System.t.sol").write_text("// Neutral regression test name; not allowed in source-only detection.\npragma solidity ^0.8.20;\ncontract CaseProbe { function test_case_flow() public {} }\n")
    (case_root / "README.md").write_text(f"This README intentionally contains a hidden answer hint for {RULE_MAP[rule]['bug_class']} and must not be read during detection.\n")
    (case_root / "writeups" / "issue.md").write_text(f"Historical-style writeup: {RULE_MAP[rule]['bug_class']} via {RULE_MAP[rule]['scenario']}. Forbidden during detection.\n")
    (case_root / "reports" / "fake_scanner.json").write_text(json.dumps({"tool": "fake", "claim": "no vulnerabilities found" if not patched else "critical issue found"}, indent=2) + "\n")
    spec = RULE_MAP[rule]
    expected = {
        "case_id": case_id,
        "is_vulnerable": not patched,
        "is_patched_control": patched,
        "bug_class": spec["bug_class"] if not patched else None,
        "control_for_bug_class": spec["bug_class"] if patched else None,
        "root_cause_rule": rule if not patched else None,
        "source_file": "src/System.sol",
        "affected_contract": contract,
        "affected_function": function,
        "affected_asset": spec["affected_asset"],
        "impact_type": spec["impact"],
        "expected_severity": spec["severity"],
        "exploit_path_tokens": exploit_tokens_for_rule(rule),
        "expected_no_report_ready": patched,
        "source_type": "synthetic_realistic" if split != "holdout" else "holdout",
        "protocol_type": PROTOCOL_FOR_RULE[rule],
    }
    (root / "expected_findings").mkdir(parents=True, exist_ok=True)
    (root / "expected_findings" / f"{case_id}.json").write_text(json.dumps(expected, indent=2) + "\n")
    return {
        "case_id": case_id,
        "corpus_split": split,
        "source_type": expected["source_type"],
        "protocol_type": PROTOCOL_FOR_RULE[rule],
        "language": "Solidity",
        "framework": "none",
        "is_vulnerable": not patched,
        "is_patched_control": patched,
        "answer_key_path": f"expected_findings/{case_id}.json",
        "detector_allowed_paths": ["src/", "contracts/"],
        "detector_forbidden_paths": ["expected_findings/", "README.md", "test/", "reports/", "writeups/"],
        "allowed_detection_modes": ["source_only", "source_plus_tests"],
        "safety": {"network_allowed": False, "secrets_allowed": False, "broadcast_allowed": False},
    }


def build_corpus(root: Path = DEFAULT_ROOT, *, force: bool = False) -> dict[str, Any]:
    if force and root.exists():
        shutil.rmtree(root)
    for part in ["vulnerable", "patched", "holdout", "expected_findings", "generated_reports", "scoring"]:
        (root / part).mkdir(parents=True, exist_ok=True)
    cases: list[dict[str, Any]] = []
    vuln_num = 1
    patched_num = 101
    for round_idx in range(2):
        for rule in BUG_ORDER:
            vuln_id = f"case_{vuln_num:03d}"
            patch_id = f"case_{patched_num:03d}"
            cases.append(write_case(root, "vulnerable", vuln_id, rule, patched=False, variant=vuln_num))
            cases.append(write_case(root, "patched", patch_id, rule, patched=True, variant=patched_num + 500))
            vuln_num += 1
            patched_num += 1
    case_num = 201
    holdout_start = case_num
    for rule in BUG_ORDER:
        case_id = f"case_{case_num:03d}"
        cases.append(write_case(root, "holdout", case_id, rule, patched=False, variant=case_num + 900))
        case_num += 1
    manifest = {
        "version": "1.0",
        "description": "Local-only OOD synthetic-realistic Solidity/EVM benchmark corpus. Detection must not read answer keys, READMEs, writeups, reports, or revealing tests in source-only mode.",
        "minimums": {
            "minimum_vulnerable_cases": 20,
            "minimum_patched_safe_cases": 20,
            "minimum_holdout_cases": 10,
            "minimum_bug_classes": 10,
            "minimum_protocol_types": 5,
        },
        "holdout_first_case_id": f"case_{holdout_start:03d}",
        "cases": cases,
    }
    (root / "corpus_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (root / "README.md").write_text("# Real-world OOD corpus\n\nLocal-only synthetic-realistic Solidity/EVM cases. README files are forbidden during detection and may contain hints.\n")
    return manifest


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Build local OOD benchmark corpus")
    p.add_argument("--root", default=str(DEFAULT_ROOT))
    p.add_argument("--force", action="store_true")
    args = p.parse_args(argv)
    manifest = build_corpus(Path(args.root), force=args.force)
    print(json.dumps({"status": "PASS", "root": args.root, "case_count": len(manifest["cases"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
