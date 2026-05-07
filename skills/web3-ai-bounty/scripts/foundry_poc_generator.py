#!/usr/bin/env python3
"""Generate bounty-grade Foundry PoC scaffolds from Lead DB/on-chain facts.

Component 5 of the Web3 audit engine. The generator writes local test/harness
artifacts only. It never modifies production contracts, never broadcasts
transactions, and generated exploit tests intentionally fail until the auditor
fills concrete exploit steps and assertions.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "1.0.0"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

CHAIN_ENV = {
    1: "MAINNET_RPC_URL",
    10: "OPTIMISM_RPC_URL",
    56: "BSC_RPC_URL",
    100: "GNOSIS_RPC_URL",
    137: "POLYGON_RPC_URL",
    8453: "BASE_RPC_URL",
    42161: "ARBITRUM_RPC_URL",
    43114: "AVAX_RPC_URL",
    59144: "LINEA_RPC_URL",
    81457: "BLAST_RPC_URL",
    534352: "SCROLL_RPC_URL",
    11155111: "SEPOLIA_RPC_URL",
}

PATTERNS: dict[str, dict[str, Any]] = {
    "erc4626-inflation": {
        "aliases": ["erc4626", "share", "donation", "inflation", "first-depositor", "vault-share"],
        "title": "ERC4626 first-depositor donation inflation",
        "test": "test_exploit_attackerStealsVictimDepositViaDonationInflation",
        "impact": "stolen-funds",
        "harnesses": [],
        "steps": [
            "Start from an empty or near-empty vault state.",
            "Attacker deposits dust shares.",
            "Attacker donates underlying directly to inflate share price.",
            "Victim performs a normal deposit and receives zero/fewer shares.",
            "Attacker redeems shares and extracts victim value.",
        ],
        "assertions": [
            "assertLt(victimShares, expectedFairShares, 'victim shares were not diluted');",
            "assertGt(attackerGain, attackerCost, 'attack not profitable');",
            "assertEq(attackerGain, victimLoss, 'attacker gain must equal victim loss');",
        ],
        "control": "Apply donation/min-share/virtual-offset protection or execute honest deposit order and assert victim receives fair shares.",
    },
    "reentrancy": {
        "aliases": ["reentrancy", "callback", "external-call-before-state", "execution-ordering"],
        "title": "Reentrancy or callback ordering",
        "test": "test_exploit_attackerReentersBeforeAccountingUpdate",
        "impact": "stolen-funds",
        "harnesses": ["ReentrantHarness"],
        "steps": [
            "Give attacker/harness a valid claim, share, or withdrawal position.",
            "Arm the harness with calldata for the reentrant function or sibling path.",
            "Call the vulnerable function so external control is transferred before state is finalized.",
            "Reenter exactly once and withdraw/claim more than entitlement.",
        ],
        "assertions": [
            "assertGt(attackerReceived, attackerEntitlement, 'attacker did not exceed entitlement');",
            "assertLt(protocolBalanceAfter, protocolBalanceBefore - attackerEntitlement, 'protocol did not lose extra funds');",
        ],
        "control": "State update before external call or nonReentrant should block the second withdrawal/claim.",
    },
    "signature-replay": {
        "aliases": ["signature", "replay", "domain", "ecrecover", "ecdsa", "nonce"],
        "title": "Signature replay or domain bypass",
        "test": "test_exploit_attackerReusesSameSignatureTwice",
        "impact": "stolen-funds",
        "harnesses": ["SignatureReplayHelper"],
        "steps": [
            "Create or import one victim authorization signature.",
            "Use the exact same bytes once in the intended path.",
            "Replay the exact same bytes in the same function or a different context.",
            "Show assets/state move twice or in the wrong market/action/chain.",
        ],
        "assertions": [
            "SignatureReplayHelper.assertSameSignature(signature, replayedSignature);",
            "assertGt(attackerGain, 0, 'replay produced no gain');",
            "assertEq(victimLoss, attackerGain, 'victim loss did not fund attacker');",
        ],
        "control": "Nonce consumption, deadline, chainId, verifyingContract, action, market, and recipient binding should reject replay.",
    },
    "oracle-bad-debt": {
        "aliases": ["oracle", "price", "stale", "spot", "twap", "bad-debt", "pyth", "chainlink"],
        "title": "Oracle manipulation or stale price bad debt",
        "test": "test_exploit_attackerCreatesBadDebtWithBadPrice",
        "impact": "bad-debt",
        "harnesses": ["MutableOracleHarness"],
        "steps": [
            "Set baseline collateral, debt, and oracle price.",
            "Manipulate or force stale/unsafe oracle value consumed by the target.",
            "Borrow/mint/redeem/settle against the bad price.",
            "Restore price and assert the protocol is undercollateralized or attacker keeps profit.",
        ],
        "assertions": [
            "assertGt(protocolBadDebt, 0, 'protocol has no bad debt');",
            "assertGt(attackerProfitAfterCosts, 0, 'attack is not profitable after costs');",
        ],
        "control": "Freshness/confidence/TWAP/decimal checks should block or reduce the manipulated price path.",
    },
    "access-control": {
        "aliases": ["access", "authorization", "auth", "role", "onlyowner", "permission", "sibling"],
        "title": "Sibling access-control bypass",
        "test": "test_exploit_attackerPerformsUnauthorizedPrivilegedAction",
        "impact": "unauthorized-privileged-action",
        "harnesses": [],
        "steps": [
            "Prove attacker lacks the role/owner/operator permission required by the guarded path.",
            "Call the guarded path and expect revert.",
            "Call the unguarded sibling/helper/batch path as attacker.",
            "Assert restricted state, role, implementation, parameter, or funds changed.",
        ],
        "assertions": [
            "vm.expectRevert();",
            "assertEq(restrictedStateAfter, attackerChosenValue, 'unauthorized state change failed');",
        ],
        "control": "Authorized role can execute intended path; attacker cannot execute either path after shared guard.",
    },
    "proxy-initialization": {
        "aliases": ["proxy", "initialize", "initializer", "reinitialize", "reinit", "upgrade"],
        "title": "Proxy initialization or reinitialization takeover",
        "test": "test_exploit_attackerTakesOverInitialization",
        "impact": "unauthorized-privileged-action",
        "harnesses": [],
        "steps": [
            "Fork deployed proxy/implementation state or deploy matching local setup.",
            "Record current owner/admin/role baseline.",
            "Attacker calls initialize/reinitialize/setup path.",
            "Assert attacker gained owner/admin/signer/guardian or changed implementation/security state.",
        ],
        "assertions": [
            "assertNotEq(ownerBefore, attacker, 'bad baseline');",
            "assertEq(ownerAfter, attacker, 'attacker did not gain ownership');",
        ],
        "control": "initializer/reinitializer guard or _disableInitializers should revert attacker setup call.",
    },
    "bridge-double-finalize": {
        "aliases": ["double finalize", "double-finalize", "finalize", "retry", "cancel", "cross-chain", "oapp", "oft"],
        "title": "Bridge finalize/retry/cancel double release",
        "test": "test_exploit_attackerDoubleFinalizesBridgeMessage",
        "impact": "stolen-funds",
        "harnesses": ["MaliciousBridgeReceiverHarness"],
        "steps": [
            "Create one legitimate source lock/burn/message or fork existing message state.",
            "Finalize once through the intended path.",
            "Reenter/retry/cancel/finalize again before consumed/refunded state is shared.",
            "Assert attacker receives more than locked/burned or gets refund plus destination release.",
        ],
        "assertions": [
            "assertGt(attackerBridgeGain, amountLocked, 'attacker did not receive more than locked');",
            "assertEq(messageReleaseCount, 2, 'message was not executed twice');",
        ],
        "control": "Consumed/refunded flags set before external call and shared across retry/cancel/finalize should block duplicate release.",
    },
    "accounting-desync": {
        "aliases": ["accounting", "desync", "reward", "rewards", "checkpoint", "index", "loss", "emergency", "trigger"],
        "title": "Accounting desync or reward/loss shift",
        "test": "test_exploit_attackerStealsUnearnedAccountingValue",
        "impact": "stolen-funds",
        "harnesses": [],
        "steps": [
            "Set victim/protocol baseline accounting before the stale update.",
            "Move funds/rewards/loss into the system without the expected checkpoint or user snapshot.",
            "Attacker enters/exits/triggers update at favorable time.",
            "Assert attacker receives value that belonged to victim/protocol or avoids loss/debt.",
        ],
        "assertions": [
            "assertGt(attackerGain, 0, 'attacker did not gain from stale accounting');",
            "assertEq(attackerGain, victimOrProtocolLoss, 'value shift not proven');",
        ],
        "control": "Checkpoint before balance change or shared internal accounting path should assign value to correct cohort.",
    },
    "bridge-forged-message": {
        "aliases": ["forged message", "unproven message", "arbitrary-transfer", "arbitrary transfer", "zero root", "acceptable root", "bridge message"],
        "title": "Bridge forged/unproven message execution",
        "test": "test_exploit_attackerProcessesForgedBridgeMessage",
        "impact": "stolen-funds",
        "harnesses": [],
        "steps": [
            "Create or fork destination-side bridge state with escrowed canonical assets or mint authority.",
            "Construct a message body that names the bridge/router recipient, token identifier, attacker recipient, and amount.",
            "Call the destination message processor without a valid source proof/signature path.",
            "Assert the message reaches the bridge/router and releases or mints assets to the attacker.",
        ],
        "assertions": [
            "assertGt(attackerGain, 0, 'forged message produced no attacker gain');",
            "assertEq(protocolLoss, attackerGain, 'attacker gain must be funded by bridge/protocol loss');",
            "assertTrue(messageWasProcessed, 'forged message was not processed');",
        ],
        "control": "A nonzero trusted root, explicit zero-root rejection, proof validation, or consumed-message check should reject the forged message before bridge execution.",
    },
    "nonstandard-token": {
        "aliases": ["unchecked", "false-return", "no-return", "fee-on-transfer", "rebasing", "token-return", "erc20"],
        "title": "Non-standard token or unchecked transfer accounting desync",
        "test": "test_exploit_attackerInflatesAccountingWithNonstandardToken",
        "impact": "stolen-funds",
        "harnesses": ["FalseReturnERC20Harness"],
        "steps": [
            "Use an in-scope non-standard token or prove arbitrary token support is in scope.",
            "Make token transfer fail, return false, fee, or rebase while protocol credits full amount.",
            "Withdraw/borrow/redeem against inflated accounting.",
            "Assert protocol accounted assets exceed real token balance and attacker extracts value.",
        ],
        "assertions": [
            "assertGt(accountedAssets, realTokenBalance, 'accounting not inflated');",
            "assertGt(attackerGain, 0, 'desync not monetized');",
        ],
        "control": "Use balanceBefore/balanceAfter or SafeERC20 return validation to credit actual received amount.",
    },
    "generic": {
        "aliases": [],
        "title": "Generic Web3 exploit scaffold",
        "test": "test_exploit_attackerBreaksInvariant",
        "impact": "unknown",
        "harnesses": [],
        "steps": [
            "State the invariant in one sentence.",
            "Set up honest baseline with exact balances/accounting.",
            "Execute the minimum attacker-controlled sequence.",
            "Assert concrete accepted impact.",
        ],
        "assertions": [
            "assertGt(concreteImpact, 0, 'impact not proven');",
        ],
        "control": "Honest path or patched behavior preserves the invariant.",
    },
}


HARNESS_SNIPPETS: dict[str, str] = {
    "ReentrantHarness": r'''
contract ReentrantHarness {
    address public target;
    bytes public reenterData;
    bool public entered;

    constructor(address _target) {
        target = _target;
    }

    function arm(bytes memory _reenterData) external {
        reenterData = _reenterData;
        entered = false;
    }

    receive() external payable {
        if (!entered && reenterData.length != 0) {
            entered = true;
            (bool ok,) = target.call(reenterData);
            ok;
        }
    }
}
''',
    "MutableOracleHarness": r'''
contract MutableOracleHarness {
    int256 public price;
    uint8 public decimals;
    uint256 public updatedAt;
    bool public shouldRevert;

    constructor(int256 _price, uint8 _decimals) {
        price = _price;
        decimals = _decimals;
        updatedAt = block.timestamp;
    }

    function setPrice(int256 _price) external {
        price = _price;
        updatedAt = block.timestamp;
    }

    function setUpdatedAt(uint256 _updatedAt) external {
        updatedAt = _updatedAt;
    }

    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80) {
        require(!shouldRevert, "oracle revert");
        return (1, price, updatedAt, updatedAt, 1);
    }
}
''',
    "SignatureReplayHelper": r'''
library SignatureReplayHelper {
    function sameSignature(bytes memory a, bytes memory b) internal pure returns (bool) {
        return keccak256(a) == keccak256(b);
    }

    function assertSameSignature(bytes memory a, bytes memory b) internal pure {
        require(sameSignature(a, b), "not same signature");
    }
}
''',
    "FalseReturnERC20Harness": r'''
contract FalseReturnERC20Harness {
    string public name = "FalseReturnToken";
    string public symbol = "FALSE";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    bool public returnFalse;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function setReturnFalse(bool value) external {
        returnFalse = value;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return !returnFalse;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return !returnFalse;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "allowance");
        allowance[from][msg.sender] = allowed - amount;
        _transfer(from, to, amount);
        return !returnFalse;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}
''',
    "MaliciousBridgeReceiverHarness": r'''
contract MaliciousBridgeReceiverHarness {
    address public bridge;
    bytes public savedCalldata;
    bool public entered;

    constructor(address _bridge) {
        bridge = _bridge;
    }

    function arm(bytes calldata _calldata) external {
        savedCalldata = _calldata;
        entered = false;
    }

    function onBridgeReceive() external {
        if (!entered && savedCalldata.length != 0) {
            entered = true;
            (bool ok,) = bridge.call(savedCalldata);
            ok;
        }
    }
}
''',
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: Path | None) -> Any:
    if not path:
        return None
    return json.loads(path.read_text(errors="replace"))


def save_text(path: Path, text: str, force: bool) -> None:
    if path.exists() and not force:
        raise SystemExit(f"Refusing to overwrite existing file: {path} (use --force)")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def save_json(path: Path, data: Any, force: bool) -> None:
    save_text(path, json.dumps(data, indent=2) + "\n", force)


def normalize_address(value: str | None) -> str | None:
    if not value:
        return None
    v = value.strip()
    if not re.fullmatch(r"0x[a-fA-F0-9]{40}", v):
        return None
    return "0x" + v[2:].lower()


def solidity_address(value: str | None) -> str:
    return f"address({normalize_address(value) or ZERO_ADDRESS})"


def safe_ident(value: str, fallback: str = "Generated") -> str:
    parts = re.split(r"[^A-Za-z0-9]+", value or "")
    out = "".join(p[:1].upper() + p[1:] for p in parts if p)
    if not out:
        out = fallback
    if out[0].isdigit():
        out = fallback + out
    return out


def safe_snake(value: str, fallback: str = "generated") -> str:
    text = re.sub(r"[^A-Za-z0-9]+", "_", value or "").strip("_").lower()
    return text or fallback


def detect_project_pragma(project_root: str | Path | None) -> str:
    """Return a Foundry-test pragma compatible with the target project.

    The generator defaults to modern Solidity for greenfield scaffolds, but many
    historical bounty targets pin older compilers. If foundry.toml declares an
    exact solc_version, emit that exact pragma so generated tests do not break
    the project before the auditor writes any exploit logic.
    """
    if not project_root:
        return "^0.8.20"
    toml_path = Path(project_root) / "foundry.toml"
    try:
        text = toml_path.read_text(errors="replace")
    except Exception:
        return "^0.8.20"
    match = re.search(r"solc_version\s*=\s*['\"]([^'\"]+)['\"]", text)
    if not match:
        return "^0.8.20"
    version = match.group(1).strip()
    if re.fullmatch(r"\d+\.\d+\.\d+(?:\+commit\.[0-9a-fA-F]+)?", version):
        return version.split("+", 1)[0]
    return version or "^0.8.20"


def git_value(root: Path, args: list[str]) -> str | None:
    try:
        return subprocess.check_output(["git", *args], cwd=root, text=True, stderr=subprocess.DEVNULL).strip() or None
    except Exception:
        return None


def find_lead(db: dict[str, Any] | None, lead_id: str | None) -> dict[str, Any] | None:
    if not db:
        return None
    leads = db.get("leads") or []
    if lead_id:
        for lead in leads:
            if lead.get("id") == lead_id:
                return lead
        raise SystemExit(f"Lead not found: {lead_id}")
    if leads:
        return leads[0]
    return None


def first_location(lead: dict[str, Any] | None) -> dict[str, Any]:
    if not lead:
        return {}
    locations = lead.get("locations") or []
    return locations[0] if locations else {}


def pick_pattern(bug_class: str | None, title: str | None = None, impact_type: str | None = None) -> tuple[str, dict[str, Any]]:
    haystack = " ".join([bug_class or "", title or "", impact_type or ""]).lower()
    for key, pattern in PATTERNS.items():
        if key == "generic":
            continue
        if any(alias in haystack for alias in pattern.get("aliases", [])):
            return key, pattern
    return "generic", PATTERNS["generic"]


def find_code_function(code_index: dict[str, Any] | None, contract: str | None, function: str | None) -> dict[str, Any] | None:
    if not code_index or not contract:
        return None
    for c in code_index.get("contracts", []):
        if c.get("name") != contract:
            continue
        if not function:
            return None
        for f in c.get("functions", []):
            if f.get("name") == function:
                return f
    return None


def default_out_path(args: argparse.Namespace, lead: dict[str, Any] | None, pattern_key: str) -> Path:
    if args.out:
        return Path(args.out)
    lead_part = (lead or {}).get("id") or f"P-{uuid.uuid4().hex[:8]}"
    name = safe_ident(f"{lead_part} {pattern_key} PoC", "GeneratedPoC")
    return Path(args.project_root) / "test" / f"{name}.t.sol"


def default_metadata_path(out: Path, args: argparse.Namespace) -> Path:
    if args.metadata:
        return Path(args.metadata)
    text = str(out)
    if text.endswith(".t.sol"):
        return Path(text[:-6] + ".plan.json")
    return out.with_suffix(out.suffix + ".plan.json")


def derive_context(args: argparse.Namespace) -> dict[str, Any]:
    lead_db = load_json(args.lead_db)
    lead = find_lead(lead_db, args.lead_id)
    onchain = load_json(args.onchain)
    code_index = load_json(args.code_index)
    loc = first_location(lead)
    impact = (lead or {}).get("impact") or {}
    hypothesis = (lead or {}).get("hypothesis") or {}
    target_report = (onchain or {}).get("target") or {}
    proxy = target_report.get("proxy") or {}
    token_balances = target_report.get("token_balances") or []
    first_token = token_balances[0].get("token") if token_balances and isinstance(token_balances[0], dict) else None
    contract = args.target_contract or loc.get("contract") or (lead or {}).get("contract")
    function = args.target_function or loc.get("function")
    target = normalize_address(args.target_address) or normalize_address(loc.get("address")) or normalize_address(target_report.get("address"))
    implementation = normalize_address(args.implementation) or normalize_address(loc.get("implementation")) or normalize_address(proxy.get("effective_implementation"))
    asset = normalize_address(args.asset) or normalize_address(first_token)
    chain_id = args.chain_id or loc.get("chain_id") or target_report.get("chain_id")
    block_number = args.block or target_report.get("block_number")
    bug_class = args.bug_class or (lead or {}).get("bug_class") or "generic"
    impact_type = args.impact_type or impact.get("type") or None
    pattern_key, pattern = pick_pattern(bug_class, (lead or {}).get("title"), impact_type)
    if args.pattern:
        pattern_key, pattern = args.pattern, PATTERNS.get(args.pattern, PATTERNS["generic"])
    rpc_env = args.rpc_env or (CHAIN_ENV.get(int(chain_id)) if chain_id else None) or "RPC_URL"
    mode = args.mode
    if mode == "auto":
        mode = "fork" if target else "local"
    code_fn = find_code_function(code_index, contract, function)
    return {
        "lead_db": lead_db,
        "lead": lead,
        "onchain": onchain,
        "code_index": code_index,
        "code_function": code_fn,
        "location": loc,
        "contract": contract,
        "function": function,
        "target": target,
        "implementation": implementation,
        "asset": asset,
        "chain_id": int(chain_id) if chain_id is not None else None,
        "block_number": int(block_number) if block_number is not None else None,
        "bug_class": bug_class,
        "impact_type": impact_type or pattern.get("impact"),
        "hypothesis": hypothesis,
        "pattern_key": pattern_key,
        "pattern": pattern,
        "rpc_env": rpc_env,
        "mode": mode,
    }


def harnesses_for(pattern: dict[str, Any], include: str) -> list[str]:
    if include == "none":
        return []
    if include == "all":
        return sorted(HARNESS_SNIPPETS)
    return list(pattern.get("harnesses") or [])


def solidity_header(ctx: dict[str, Any], contract_name: str, args: argparse.Namespace) -> str:
    lead = ctx.get("lead") or {}
    hypothesis = ctx.get("hypothesis") or {}
    code_fn = ctx.get("code_function") or {}
    pragma = args.pragma or detect_project_pragma(args.project_root)
    lines = [
        "// SPDX-License-Identifier: UNLICENSED",
        f"pragma solidity {pragma};",
        "",
        'import "forge-std/Test.sol";',
        "",
        "interface IERC20Like {",
        "    function balanceOf(address account) external view returns (uint256);",
        "    function transfer(address to, uint256 amount) external returns (bool);",
        "    function approve(address spender, uint256 amount) external returns (bool);",
        "}",
        "",
        "interface ITargetLike {",
        "    // Add only the target functions needed for the exploit/control path.",
    ]
    if code_fn.get("signature"):
        lines.append(f"    // Code index signature hint: {code_fn.get('signature')}")
    else:
        lines.append("    // Example: function vulnerableFunction(uint256 amount) external;")
    lines.extend([
        "}",
        "",
        "/**",
        " * @notice Generated PoC scaffold. It intentionally fails until exploit steps and assertions are implemented.",
        " * Do not submit this scaffold as proof. Replace TODO sections with a minimal passing exploit/control test.",
    ])
    if lead.get("id"):
        lines.append(f" * Lead: {lead.get('id')} - {lead.get('title', '')}")
    if hypothesis.get("exploit_sentence"):
        lines.append(f" * Hypothesis: {hypothesis.get('exploit_sentence')}")
    lines.extend([
        " */",
        f"contract {contract_name} is Test {{",
        f"    address internal constant TARGET = {solidity_address(ctx.get('target'))};",
        f"    address internal constant IMPLEMENTATION = {solidity_address(ctx.get('implementation'))};",
        f"    address internal constant ASSET = {solidity_address(ctx.get('asset'))};",
        f"    uint256 internal constant FORK_BLOCK = {ctx.get('block_number') or 0};",
        f"    string internal constant RPC_ENV = \"{ctx.get('rpc_env') or 'RPC_URL'}\";",
        f"    bool internal constant USE_FORK = {'true' if ctx.get('mode') == 'fork' else 'false'};",
        "",
        "    uint256 internal forkId;",
        "    address internal alice = makeAddr(\"alice\");",
        "    address internal victim = makeAddr(\"victim\");",
        "    address internal attacker = makeAddr(\"attacker\");",
        "    address internal keeper = makeAddr(\"keeper\");",
        "",
        "    function setUp() public {",
        "        if (USE_FORK) {",
        "            if (FORK_BLOCK == 0) {",
        "                forkId = vm.createFork(vm.envString(RPC_ENV));",
        "            } else {",
        "                forkId = vm.createFork(vm.envString(RPC_ENV), FORK_BLOCK);",
        "            }",
        "            vm.selectFork(forkId);",
        "        }",
        "",
        "        vm.label(alice, \"alice\");",
        "        vm.label(victim, \"victim\");",
        "        vm.label(attacker, \"attacker\");",
        "        vm.label(keeper, \"keeper\");",
        "        if (TARGET != address(0)) vm.label(TARGET, \"target\");",
        "        if (IMPLEMENTATION != address(0)) vm.label(IMPLEMENTATION, \"implementation\");",
        "        if (ASSET != address(0)) vm.label(ASSET, \"asset\");",
        "",
        "        // Give local actors ETH for gas/value in local or fork simulations. No real funds are used.",
        "        vm.deal(attacker, 100 ether);",
        "        vm.deal(victim, 100 ether);",
        "        vm.deal(alice, 100 ether);",
        "    }",
        "",
        "    function _requireConfiguredTarget() internal pure {",
        "        require(TARGET != address(0), \"configure TARGET before running PoC\");",
        "    }",
        "",
        "    function _assetBalance(address account) internal view returns (uint256) {",
        "        if (ASSET == address(0)) return account.balance;",
        "        return IERC20Like(ASSET).balanceOf(account);",
        "    }",
        "",
    ])
    return "\n".join(lines)


def control_test(pattern: dict[str, Any]) -> str:
    return f'''    function test_control_honestPathWorks() public {{
        _requireConfiguredTarget();

        // CONTROL OBJECTIVE:
        // {pattern.get('control')}
        //
        // TODO:
        // 1. Build the honest baseline state.
        // 2. Execute the intended user flow.
        // 3. Assert exact balances/accounting/roles are correct.

        fail("TODO: implement honest-path control assertions before relying on this PoC");
    }}
'''


def exploit_test(pattern: dict[str, Any], ctx: dict[str, Any]) -> str:
    steps = "\n".join(f"        // {i}. {step}" for i, step in enumerate(pattern.get("steps") or [], start=1))
    assertions = "\n".join(f"        // {a}" for a in pattern.get("assertions") or [])
    hypothesis = (ctx.get("hypothesis") or {}).get("exploit_sentence") or "TODO: state the concrete exploit sentence."
    return f'''    function {pattern.get('test')}() public {{
        _requireConfiguredTarget();

        // EXPLOIT HYPOTHESIS:
        // {hypothesis}
        //
        // BASELINE: capture balances/state before attack.
        uint256 attackerBefore = _assetBalance(attacker);
        uint256 victimBefore = _assetBalance(victim);
        uint256 protocolBefore = _assetBalance(TARGET);
        attackerBefore;
        victimBefore;
        protocolBefore;

        // ATTACK PLAN:
{steps}
        //
        // TODO: replace placeholders with exact calldata/function calls.
        vm.startPrank(attacker);
        // Example low-level placeholder; replace with typed interface calls once signatures are known.
        // (bool ok,) = TARGET.call(abi.encodeWithSignature("vulnerableFunction(uint256)", 1));
        // require(ok, "first exploit action failed");
        vm.stopPrank();

        // PROOF TARGETS:
{assertions}
        uint256 attackerAfter = _assetBalance(attacker);
        uint256 victimAfter = _assetBalance(victim);
        uint256 protocolAfter = _assetBalance(TARGET);
        attackerAfter;
        victimAfter;
        protocolAfter;

        fail("TODO: implement exploit steps and concrete impact assertions");
    }}
'''


def solidity_footer() -> str:
    return "}\n"


def build_solidity(ctx: dict[str, Any], contract_name: str, args: argparse.Namespace) -> tuple[str, list[str]]:
    pattern = ctx["pattern"]
    harnesses = harnesses_for(pattern, args.include_harness)
    parts = [solidity_header(ctx, contract_name, args).rstrip(), control_test(pattern).rstrip(), exploit_test(pattern, ctx).rstrip()]
    text = "\n\n".join(parts) + "\n" + solidity_footer().rstrip() + "\n"
    for harness in harnesses:
        text += "\n" + HARNESS_SNIPPETS[harness].strip() + "\n"
    return text, harnesses


def build_plan(ctx: dict[str, Any], out: Path, metadata: Path, contract_name: str, harnesses: list[str], args: argparse.Namespace) -> dict[str, Any]:
    lead = ctx.get("lead") or {}
    root = Path(args.project_root).resolve()
    command = f"forge test --match-path {out} --match-test {ctx['pattern'].get('test')} -vvvv"
    plan = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "generator": {
            "name": "foundry_poc_generator.py",
            "version": "1.0.0",
        },
        "inputs": {
            "lead_db": str(args.lead_db) if args.lead_db else None,
            "lead_id": args.lead_id or lead.get("id"),
            "onchain": str(args.onchain) if args.onchain else None,
            "code_index": str(args.code_index) if args.code_index else None,
        },
        "project": {
            "root": str(root),
            "branch": git_value(root, ["rev-parse", "--abbrev-ref", "HEAD"]),
            "commit": git_value(root, ["rev-parse", "HEAD"]),
        },
        "lead": {
            "id": lead.get("id"),
            "title": lead.get("title") or args.title,
            "bug_class": ctx.get("bug_class"),
            "status": lead.get("status"),
            "impact_type": ctx.get("impact_type"),
            "exploit_sentence": (ctx.get("hypothesis") or {}).get("exploit_sentence"),
        },
        "target": {
            "mode": ctx.get("mode"),
            "chain_id": ctx.get("chain_id"),
            "block_number": ctx.get("block_number"),
            "rpc_env": ctx.get("rpc_env"),
            "address": ctx.get("target"),
            "implementation": ctx.get("implementation"),
            "asset": ctx.get("asset"),
            "contract": ctx.get("contract"),
            "function": ctx.get("function"),
        },
        "pattern": {
            "id": ctx.get("pattern_key"),
            "title": ctx["pattern"].get("title"),
            "test_name": ctx["pattern"].get("test"),
            "steps": ctx["pattern"].get("steps"),
            "assertions": ctx["pattern"].get("assertions"),
            "control": ctx["pattern"].get("control"),
            "harnesses": harnesses,
        },
        "output": {
            "solidity_path": str(out),
            "metadata_path": str(metadata),
            "test_contract": contract_name,
            "poc_status": "SCAFFOLD",
            "intentionally_fails_until_completed": True,
        },
        "run": {
            "narrow_command": command,
            "after_completion_command": command,
            "lead_db_command_after_generation": f"python3 <skill-dir>/scripts/lead_db.py add-poc audit-leads.json {lead.get('id') or '<lead-id>'} --path {out} --command \"{command}\" --status PLANNED --summary \"generated scaffold; exploit assertions still TODO\"",
            "lead_db_command_after_pass": f"python3 <skill-dir>/scripts/lead_db.py add-poc audit-leads.json {lead.get('id') or '<lead-id>'} --path {out} --command \"{command}\" --status PASS --summary \"PoC passes and asserts concrete impact\"",
        },
        "todo": [
            "Replace placeholder low-level calls with typed target interface calls.",
            "Set exact victim/protocol baseline balances and accounting state.",
            "Implement exploit sequence using normal attacker privileges only.",
            "Assert both attacker gain and victim/protocol loss, bad debt, frozen funds, or unauthorized state change.",
            "Implement control test proving honest path or patched behavior blocks exploit.",
            "Run the narrow forge command and only then update Lead DB PoC status to PASS.",
        ],
        "safety": {
            "modifies_production_contracts": False,
            "broadcasts_transactions": False,
            "uses_real_private_keys": False,
            "stores_rpc_url": False,
            "local_or_fork_only": True,
        },
    }
    return plan


def print_summary(plan: dict[str, Any]) -> None:
    print("# Foundry PoC Scaffold Generated")
    print()
    print(f"Solidity: `{plan['output']['solidity_path']}`")
    print(f"Metadata: `{plan['output']['metadata_path']}`")
    print(f"Pattern: `{plan['pattern']['id']}` — {plan['pattern']['title']}")
    print(f"Test: `{plan['pattern']['test_name']}`")
    print()
    print("Run after filling TODOs:")
    print()
    print("```bash")
    print(plan["run"]["narrow_command"])
    print("```")
    print()
    print("The generated exploit test intentionally fails until concrete exploit steps and assertions are implemented.")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Generate a Foundry fork/local PoC scaffold from Web3 audit lead artifacts")
    ap.add_argument("--project-root", default=".")
    ap.add_argument("--lead-db", type=Path)
    ap.add_argument("--lead-id")
    ap.add_argument("--onchain", type=Path)
    ap.add_argument("--code-index", type=Path)
    ap.add_argument("--title")
    ap.add_argument("--bug-class")
    ap.add_argument("--impact-type")
    ap.add_argument("--pattern", choices=sorted(PATTERNS.keys()))
    ap.add_argument("--target-address")
    ap.add_argument("--implementation")
    ap.add_argument("--asset")
    ap.add_argument("--target-contract")
    ap.add_argument("--target-function")
    ap.add_argument("--chain-id", type=int)
    ap.add_argument("--block", type=int)
    ap.add_argument("--rpc-env")
    ap.add_argument("--mode", choices=["auto", "fork", "local"], default="auto")
    ap.add_argument("--include-harness", choices=["auto", "none", "all"], default="auto")
    ap.add_argument("--contract-name")
    ap.add_argument("--pragma", help="override generated Solidity pragma, e.g. '0.7.6' or '^0.8.20'")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--metadata", type=Path)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--json", action="store_true", help="print metadata JSON instead of Markdown summary")
    return ap


def main() -> int:
    args = build_parser().parse_args()
    ctx = derive_context(args)
    out = default_out_path(args, ctx.get("lead"), ctx["pattern_key"])
    metadata = default_metadata_path(out, args)
    contract_name = args.contract_name or safe_ident(f"{(ctx.get('lead') or {}).get('id', '')} {ctx['pattern_key']} PoC", "GeneratedPoC")
    solidity, harnesses = build_solidity(ctx, contract_name, args)
    plan = build_plan(ctx, out, metadata, contract_name, harnesses, args)
    save_text(out, solidity, args.force)
    save_json(metadata, plan, args.force)
    if args.json:
        print(json.dumps(plan, indent=2))
    else:
        print_summary(plan)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
