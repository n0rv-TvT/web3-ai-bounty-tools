#!/usr/bin/env python3
"""Generate isolated Foundry PoC scaffolds from selected post-hoc candidates.

Generated scaffolds are local-only and intentionally do not modify production
source. A scaffold is not a confirmed PoC and never counts as a finding until a
separate execution gate runs a completed local test with impact assertions.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from frozen_output_loader import PUBLIC_ROOT

PRECISION_REGENERATION_DIR = "precision_regeneration"


def precision_dir(root: Path) -> Path:
    out = root / "scoring" / PRECISION_REGENERATION_DIR
    out.mkdir(parents=True, exist_ok=True)
    return out


def generated_root(root: Path) -> Path:
    out = root / "generated_pocs"
    out.mkdir(parents=True, exist_ok=True)
    return out


def repaired_execution_dir(root: Path) -> Path:
    out = root / "scoring" / "repaired_candidate_execution"
    out.mkdir(parents=True, exist_ok=True)
    return out


def load_json(path: Path, default: dict[str, Any] | None = None) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace")) if path.exists() else (default or {})


def split_selection_path(root: Path, split: str) -> Path:
    return root / "scoring" / f"{split.replace('-', '_')}_poc_candidate_selection.json"


def safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", value).strip("_") or "GeneratedPoC"


def solidity_string(value: Any) -> str:
    return str(value or "").replace("\\", "\\\\").replace('"', '\\"')[:240]


def foundry_toml() -> str:
    return """[profile.default]\nsrc = 'src'\ntest = 'test'\nout = 'out'\nlibs = []\nsolc_version = '0.8.20'\n"""


def vertical_slice_foundry_toml() -> str:
    return """[profile.default]\nsrc = 'src'\ntest = 'test'\nout = 'out'\nlibs = []\n"""


def as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def candidate_contract_source(candidate: dict[str, Any]) -> str:
    contract_name = safe_id(f"GeneratedPoC_{candidate.get('candidate_id')}")
    sequence = candidate.get("exploit_sequence") or []
    if not isinstance(sequence, list):
        sequence = [str(sequence)]
    minimal = candidate.get("minimal_poc_idea") or {}
    setup = minimal.get("setup") or candidate.get("state_setup") or {}
    actors = minimal.get("actors") or (candidate.get("state_setup") or {}).get("actors") or []
    assertions = as_list(candidate.get("assertion") or minimal.get("assertions") or (candidate.get("assertion_plan") or {}).get("assertions"))
    assumptions = as_list(candidate.get("preconditions")) + ["manual source trace must confirm reachability before execution"]
    missing_dependencies = [
        "local harness/mocks for token, delegation, reward, permission, or external integration behavior",
        "constructor/deployment wiring for the target lifecycle",
        "manual implementation of concrete state assertions before execution",
    ]
    comments = []
    comments.append("    // Scaffold only: post-hoc spent-holdout regression only; not evidence and not report-ready.")
    comments.append("    // Target: " + solidity_string(f"{candidate.get('file_path') or candidate.get('file')}::{candidate.get('contract')}.{candidate.get('function')}"))
    comments.append("    // Affected asset/state: " + solidity_string(candidate.get("affected_asset")))
    comments.append("    // Actors: " + solidity_string(", ".join(str(a) for a in actors)))
    comments.append("    // Setup/preconditions: " + solidity_string(json.dumps(setup, sort_keys=True)))
    for i, precondition in enumerate(assumptions[:8], start=1):
        comments.append(f"    // Precondition {i}: {solidity_string(precondition)}")
    for i, step in enumerate(sequence[:8], start=1):
        comments.append(f"    // Exploit step {i}: {solidity_string(step)}")
    for i, assertion in enumerate(assertions[:6], start=1):
        comments.append(f"    // Assertion {i}: {solidity_string(assertion)}")
    for i, dependency in enumerate(missing_dependencies, start=1):
        comments.append(f"    // Missing dependency {i}: {solidity_string(dependency)}")
    comments.append("    // Expected vulnerable behavior: source-supported hypothesis should change unauthorized/security-sensitive state if reachable.")
    comments.append("    // Execution preflight: no network, no fork, no broadcasts, no secrets, no dependency install, no production source modification.")
    comments_text = "\n".join(comments)
    kill = solidity_string(candidate.get("kill_condition"))
    return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Scaffold only: post-hoc spent-holdout regression candidate, not a confirmed finding.
contract {contract_name} {{
    event Candidate(string hypothesisId, string contractName, string functionName);

    function test_scaffold_documents_required_exploit_path() public {{
        emit Candidate("{solidity_string(candidate.get('hypothesis_id'))}", "{solidity_string(candidate.get('contract'))}", "{solidity_string(candidate.get('function'))}");
{comments_text}
        // Kill condition: {kill}
        bool executedImpactProof = false;
        require(!executedImpactProof, "scaffold only; no impact proof executed");
    }}
}}
"""


def patch_regression_contract_source(plan: dict[str, Any]) -> str:
    pair_id = safe_id(str(plan.get("pair_id") or "patch_regression"))
    vuln = plan.get("test_plan", {}).get("vulnerable_test", {})
    patched = plan.get("test_plan", {}).get("patched_test", {})
    steps = vuln.get("attack_steps") or []
    comments = "\n".join(f"    // Shared step {i + 1}: {solidity_string(step)}" for i, step in enumerate(steps[:8]))
    return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Patch-regression scaffold only. It documents the vulnerable and patched controls.
contract GeneratedPatchRegression_{pair_id} {{
    function test_scaffold_vulnerable_path_requires_manual_completion() public {{
{comments}
        // Vulnerable assertion target: {solidity_string(vuln.get('assertion'))}
        bool vulnerableImpactProven = false;
        require(!vulnerableImpactProven, "scaffold only; vulnerable proof not executed");
    }}

    function test_scaffold_patched_path_requires_manual_completion() public {{
        // Expected patched result: {solidity_string(patched.get('expected_result'))}
        // Patched assertion target: {solidity_string(patched.get('assertion'))}
        bool patchedControlProven = false;
        require(!patchedControlProven, "scaffold only; patched control not executed");
    }}
}}
"""


def write_project(out_dir: Path, source: str, manifest: dict[str, Any], *, post_hoc_regression_only: bool = True) -> dict[str, Any]:
    (out_dir / "src").mkdir(parents=True, exist_ok=True)
    (out_dir / "test").mkdir(parents=True, exist_ok=True)
    (out_dir / "foundry.toml").write_text(foundry_toml())
    test_path = out_dir / "test" / "GeneratedPoC.t.sol"
    test_path.write_text(source)
    manifest = {
        **manifest,
        "status": "PASS",
        "cwd": ".",
        "command": "forge test --match-path test/GeneratedPoC.t.sol -vv",
        "generated_files": ["foundry.toml", "test/GeneratedPoC.t.sol"],
        "requires_network": False,
        "requires_fork": False,
        "network_used": False,
        "broadcasts_used": False,
        "requires_secrets": False,
        "secrets_accessed": False,
        "reads_environment": False,
        "dependency_install_required": False,
        "dependency_install_allowed": False,
        "modifies_production_source": False,
        "scaffold_only": True,
        "execution_approved": False,
        "executed": False,
        "execution_block_reason": "scaffold_only_no_executed_evidence",
        "report_ready": False,
        "counts_as_finding": False,
        "post_hoc_regression_only": post_hoc_regression_only,
    }
    (out_dir / "poc_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def find_candidate_manifest(root: Path, candidate_id: str) -> Path | None:
    for manifest in generated_root(root).glob("**/poc_manifest.json"):
        payload = load_json(manifest, {})
        if payload.get("candidate_id") == candidate_id:
            return manifest
    return None


def load_vertical_selection(root: Path) -> dict[str, Any]:
    return load_json(root / "scoring" / "poc_vertical_slice_candidate_selection.json", {})


def vertical_slice_test_source() -> str:
    return r'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal executable harness for the case_pc_0002 InvestmentManager rounding patch.
/// @dev It mirrors the relevant source lines only: calculateDepositPrice,
///      _calculateTrancheTokenAmount, _decreaseDepositLimits, and the patched
///      maxMint clamp in processDeposit. No production source is modified.

contract VulnerableInvestmentManagerHarness {
    uint256 public constant PRICE_DECIMALS = 18;
    uint128 public constant MAX_DEPOSIT = 1;
    uint128 public constant MAX_MINT = 600_000_000_000_000_000;

    uint128 public maxDeposit;
    uint128 public maxMint;
    uint256 public escrowShares;
    uint256 public userShares;

    function seedOrder() external {
        maxDeposit = MAX_DEPOSIT;
        maxMint = MAX_MINT;
        escrowShares = MAX_MINT;
        userShares = 0;
    }

    function processDepositSameAsVulnerable(uint256 currencyAmount) external returns (uint256 trancheTokenAmount) {
        uint128 _currencyAmount = uint128(currencyAmount);
        require(_currencyAmount <= maxDeposit && _currencyAmount != 0, "amount-exceeds-deposit-limits");

        uint256 depositPrice = calculateDepositPrice();
        require(depositPrice != 0, "deposit-token-price-0");

        uint128 _trancheTokenAmount = _calculateTrancheTokenAmount(_currencyAmount, depositPrice);
        _decreaseDepositLimits(_currencyAmount, _trancheTokenAmount);

        // This mirrors InvestmentManager._deposit -> lPool.transferFrom(escrow, user, trancheTokenAmount).
        // The vulnerable value can exceed the escrowed/minted maxMint because depositPrice rounded down.
        require(escrowShares >= _trancheTokenAmount, "InvestmentManager/trancheTokens-transfer-failed");
        escrowShares -= _trancheTokenAmount;
        userShares += _trancheTokenAmount;
        return _trancheTokenAmount;
    }

    function calculateDepositPrice() public view returns (uint256) {
        if (maxMint == 0) return 0;
        return uint256(maxDeposit) * 10 ** PRICE_DECIMALS / uint256(maxMint);
    }

    function _calculateTrancheTokenAmount(uint128 currencyAmount, uint256 price) internal pure returns (uint128) {
        return uint128(uint256(currencyAmount) * 10 ** PRICE_DECIMALS / price);
    }

    function _decreaseDepositLimits(uint128 currencyAmount, uint128 trancheTokens) internal {
        maxDeposit = maxDeposit < currencyAmount ? 0 : maxDeposit - currencyAmount;
        maxMint = maxMint < trancheTokens ? 0 : maxMint - trancheTokens;
    }
}

contract PatchedInvestmentManagerHarness is VulnerableInvestmentManagerHarness {
    function processDepositSameAttackPatched(uint256 currencyAmount) external returns (uint256 trancheTokenAmount) {
        uint128 _currencyAmount = uint128(currencyAmount);
        require(_currencyAmount <= maxDeposit && _currencyAmount != 0, "amount-exceeds-deposit-limits");

        uint256 depositPrice = calculateDepositPrice();
        require(depositPrice != 0, "deposit-token-price-0");

        uint128 _trancheTokenAmount = _calculateTrancheTokenAmount(_currencyAmount, depositPrice);

        // Patched behavior from case_pc_0002_patched/src/InvestmentManager.sol lines 440-441.
        if (_trancheTokenAmount > maxMint) _trancheTokenAmount = maxMint;

        _decreaseDepositLimits(_currencyAmount, _trancheTokenAmount);
        require(escrowShares >= _trancheTokenAmount, "InvestmentManager/trancheTokens-transfer-failed");
        escrowShares -= _trancheTokenAmount;
        userShares += _trancheTokenAmount;
        return _trancheTokenAmount;
    }
}

contract GeneratedVerticalSlicePoC {
    function test_verticalSlice_vulnerableRoundingFreezesFullDepositPatchedClamps() public {
        uint128 maxDeposit = 1;
        uint128 maxMint = 600_000_000_000_000_000;

        VulnerableInvestmentManagerHarness vulnerable = new VulnerableInvestmentManagerHarness();
        vulnerable.seedOrder();

        uint256 vulnerableEscrowBefore = vulnerable.escrowShares();
        uint256 vulnerableUserBefore = vulnerable.userShares();
        (bool vulnerableOk,) = address(vulnerable).call(
            abi.encodeWithSelector(
                VulnerableInvestmentManagerHarness.processDepositSameAsVulnerable.selector,
                maxDeposit
            )
        );

        // Vulnerable assertion: same full-deposit action reverts because calculated shares exceed escrowed maxMint.
        require(!vulnerableOk, "vulnerable path unexpectedly succeeded; kill the hypothesis");
        require(vulnerable.escrowShares() == vulnerableEscrowBefore, "revert should leave escrow shares frozen");
        require(vulnerable.userShares() == vulnerableUserBefore, "user received shares despite failed processDeposit");

        PatchedInvestmentManagerHarness patched = new PatchedInvestmentManagerHarness();
        patched.seedOrder();
        uint256 patchedEscrowBefore = patched.escrowShares();

        uint256 sharesOut = patched.processDepositSameAttackPatched(maxDeposit);

        // Patched regression assertion: same attack step succeeds by clamping to maxMint and preserving accounting.
        require(sharesOut == maxMint, "patched path did not clamp to maxMint");
        require(patched.userShares() == maxMint, "patched user did not receive escrowed shares");
        require(patched.escrowShares() == patchedEscrowBefore - maxMint, "patched escrow accounting not preserved");
        require(patched.maxDeposit() == 0 && patched.maxMint() == 0, "patched limits were not consumed exactly");
    }
}
'''


def investment_manager_auth_kill_source() -> str:
    return r'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract InvestmentManagerAuthHarness {
    mapping(address => uint256) public wards;
    bool public redeemOrderIncreased;

    modifier auth() {
        require(wards[msg.sender] == 1, "Auth/not-authorized");
        _;
    }

    function rely(address user) external {
        wards[user] = 1;
    }

    function requestRedeem(uint256 trancheTokenAmount, address user) public auth {
        require(trancheTokenAmount != 0, "zero-redeem");
        require(user != address(0), "bad-user");
        redeemOrderIncreased = true;
    }
}

contract GeneratedVerticalSlicePoC {
    function test_verticalSlice_normalAttackerCannotRequestRedeemInVulnerableOrPatched() public {
        InvestmentManagerAuthHarness vulnerable = new InvestmentManagerAuthHarness();
        InvestmentManagerAuthHarness patched = new InvestmentManagerAuthHarness();

        address victim = address(0xBEEF);
        uint256 shares = 1 ether;

        (bool vulnerableOk,) = address(vulnerable).call(
            abi.encodeWithSelector(InvestmentManagerAuthHarness.requestRedeem.selector, shares, victim)
        );
        require(!vulnerableOk, "vulnerable requestRedeem reachable by normal attacker; hypothesis not killed");
        require(!vulnerable.redeemOrderIncreased(), "vulnerable unauthorized state changed");

        (bool patchedOk,) = address(patched).call(
            abi.encodeWithSelector(InvestmentManagerAuthHarness.requestRedeem.selector, shares, victim)
        );
        require(!patchedOk, "patched requestRedeem reachable by normal attacker");
        require(!patched.redeemOrderIncreased(), "patched unauthorized state changed");
    }
}
'''


def liquidity_pool_permit_kill_source() -> str:
    return r'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockSharePermit {
    bool public validPermit;

    function setValidPermit(bool value) external {
        validPermit = value;
    }

    function permit(address, address, uint256, uint256, uint8, bytes32, bytes32) external view {
        require(validPermit, "permit-invalid");
    }
}

contract MockInvestmentManager {
    bool public redeemRequested;
    address public lastOwner;
    uint256 public lastShares;

    function requestRedeem(uint256 shares, address owner) external {
        redeemRequested = true;
        lastOwner = owner;
        lastShares = shares;
    }
}

contract LiquidityPoolPermitHarness {
    MockSharePermit public share;
    MockInvestmentManager public investmentManager;

    constructor(MockSharePermit share_, MockInvestmentManager manager_) {
        share = share_;
        investmentManager = manager_;
    }

    function requestRedeemWithPermit(uint256 shares, address owner, uint256 deadline, uint8 v, bytes32 r, bytes32 s) public {
        share.permit(owner, address(investmentManager), shares, deadline, v, r, s);
        investmentManager.requestRedeem(shares, owner);
    }
}

contract GeneratedVerticalSlicePoC {
    function test_verticalSlice_invalidPermitPreventsUnauthorizedRedeemInVulnerableOrPatched() public {
        address victim = address(0xCAFE);
        uint256 shares = 1 ether;

        MockSharePermit vulnerableShare = new MockSharePermit();
        MockInvestmentManager vulnerableManager = new MockInvestmentManager();
        LiquidityPoolPermitHarness vulnerable = new LiquidityPoolPermitHarness(vulnerableShare, vulnerableManager);

        (bool vulnerableOk,) = address(vulnerable).call(
            abi.encodeWithSelector(LiquidityPoolPermitHarness.requestRedeemWithPermit.selector, shares, victim, block.timestamp + 1, uint8(27), bytes32(0), bytes32(0))
        );
        require(!vulnerableOk, "invalid permit unexpectedly changed vulnerable state");
        require(!vulnerableManager.redeemRequested(), "vulnerable unauthorized redeem request recorded");

        MockSharePermit patchedShare = new MockSharePermit();
        MockInvestmentManager patchedManager = new MockInvestmentManager();
        LiquidityPoolPermitHarness patched = new LiquidityPoolPermitHarness(patchedShare, patchedManager);

        (bool patchedOk,) = address(patched).call(
            abi.encodeWithSelector(LiquidityPoolPermitHarness.requestRedeemWithPermit.selector, shares, victim, block.timestamp + 1, uint8(27), bytes32(0), bytes32(0))
        );
        require(!patchedOk, "invalid permit unexpectedly changed patched state");
        require(!patchedManager.redeemRequested(), "patched unauthorized redeem request recorded");
    }
}
'''


def source_for_candidate(candidate_id: str) -> tuple[str, str, str]:
    if candidate_id == "POC-PREC-case_pc_0002-vulnerable-002":
        return vertical_slice_test_source(), "test_verticalSlice_vulnerableRoundingFreezesFullDepositPatchedClamps", "confirmed rounding/fund-freeze regression"
    if candidate_id == "POC-PREC-case_pc_0002-vulnerable-003":
        return investment_manager_auth_kill_source(), "test_verticalSlice_normalAttackerCannotRequestRedeemInVulnerableOrPatched", "kill normal-attacker requestRedeem hypothesis via auth gate"
    if candidate_id == "POC-PREC-case_pc_0003-vulnerable-001":
        return liquidity_pool_permit_kill_source(), "test_verticalSlice_invalidPermitPreventsUnauthorizedRedeemInVulnerableOrPatched", "kill requestRedeemWithPermit hypothesis via permit gate"
    return vertical_slice_test_source(), "test_verticalSlice_vulnerableRoundingFreezesFullDepositPatchedClamps", "generic vertical-slice harness"


def write_source_notes(root: Path, candidate: dict[str, Any], out_dir: Path, *, candidate_id: str = "") -> Path:
    pair_id = candidate.get("pair_id")
    vuln_path = root / "patched-controls" / str(candidate.get("case_id")) / str(candidate.get("file_path"))
    patched_case = str(candidate.get("case_id")).replace("_vulnerable", "_patched")
    patched_path = root / "patched-controls" / patched_case / str(candidate.get("file_path"))
    notes = f"""# PoC Vertical Slice Source Notes

- Candidate: `{candidate_id or candidate.get('candidate_id')}`
- Vulnerable file path: `{vuln_path.relative_to(root)}`
- Patched file path: `{patched_path.relative_to(root)}`
- Vulnerable function from selected candidate: `{candidate.get('contract')}.{candidate.get('function')}`
- Relevant vulnerable code path: `requestDeposit` establishes the deposit lifecycle; `handleExecutedCollectInvest` populates `orderbook.maxDeposit/maxMint`; `processDeposit` calculates tranche tokens from a rounded-down deposit price and transfers escrowed tranche tokens.
- Relevant patched function: `InvestmentManager.processDeposit`
- Security-relevant patch diff: patched `processDeposit` clamps `_trancheTokenAmount` to `orderbook[user][liquidityPool].maxMint` before `_deposit`.
- Affected state variables: `orderbook[user][liquidityPool].maxDeposit`, `orderbook[user][liquidityPool].maxMint`, escrowed tranche-token balance.
- Affected asset/accounting value: escrowed tranche tokens owed to the investor after an executed deposit order.
- Expected exploit condition: with a low rounded-down deposit price, processing the full `maxDeposit` calculates more tranche tokens than `maxMint`, so the vulnerable escrow transfer asks for more shares than were escrowed and reverts/freeze the full processing path.
- Expected patched behavior: the same processing amount clamps tranche tokens to `maxMint`, transfers exactly escrowed shares, consumes both limits, and preserves accounting.
- Patch metadata visible during detection: false; these notes are post-freeze vertical-slice adjudication.

Generated PoC directory: `{out_dir.relative_to(root)}`
Pair: `{pair_id}`
"""
    filename = f"poc_vertical_slice_{(candidate_id or str(candidate.get('candidate_id') or 'candidate')).replace('-', '_')}_source_notes.md" if candidate_id else "poc_vertical_slice_source_notes.md"
    path = root / "scoring" / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(notes)
    if candidate_id == "POC-PREC-case_pc_0002-vulnerable-002" or not (root / "scoring" / "poc_vertical_slice_source_notes.md").exists():
        (root / "scoring" / "poc_vertical_slice_source_notes.md").write_text(notes)
    return path


def load_candidate_from_batch(root: Path, candidate_id: str) -> dict[str, Any]:
    for path in [root / "scoring" / "poc_vertical_slice_batch_selection.json", root / "scoring" / "poc_vertical_slice_candidate_selection.json"]:
        payload = load_json(path, {})
        for c in payload.get("selected_candidates", []):
            if c.get("candidate_id") == candidate_id:
                return c
        if payload.get("selected_candidate_id") == candidate_id:
            return {"candidate_id": candidate_id, "pair_id": payload.get("pair_id"), "case_id": str(candidate_id).replace("POC-PREC-", "").replace("-vulnerable-002", "_vulnerable"), "file_path": payload.get("file"), "contract": payload.get("contract"), "function": payload.get("function"), "assertion_plan": payload.get("assertion_plan"), "kill_condition": payload.get("kill_condition")}
    return {"candidate_id": candidate_id}


def load_repaired_candidate(root: Path, candidate_id: str, split: str = "") -> dict[str, Any]:
    paths = []
    if split:
        paths.append(root / "scoring" / f"{split.replace('-', '_')}_repaired_poc_candidate_selection.json")
        paths.append(root / "scoring" / f"{split.replace('-', '_')}_readiness_enrichment.json")
    paths.extend([
        root / "scoring" / "repair_to_poc_repaired_candidate_selection.json",
        root / "scoring" / "fresh_confirmation_repaired_poc_candidate_selection.json",
        root / "scoring" / "repair_to_poc_readiness_enrichment.json",
    ])
    seen: set[Path] = set()
    ordered_paths: list[Path] = []
    for path in paths:
        if path not in seen:
            seen.add(path)
            ordered_paths.append(path)
    for path in ordered_paths:
        payload = load_json(path, {})
        candidates: list[dict[str, Any]] = []
        if isinstance(payload.get("selected_candidate"), dict):
            candidates.append(payload["selected_candidate"])
        if isinstance(payload.get("candidate"), dict):
            candidates.append(payload["candidate"])
        candidates.extend([c for c in payload.get("selected_candidates", []) if isinstance(c, dict)])
        candidates.extend([c for c in payload.get("repaired_candidates", []) if isinstance(c, dict)])
        for candidate in candidates:
            if candidate_id in {str(candidate.get("candidate_id") or ""), str(candidate.get("repaired_candidate_id") or ""), str(candidate.get("hypothesis_id") or "")}:
                return candidate
    return {}


def repaired_scaffold_output_subdir(split: str) -> str:
    if split == "fresh-v8":
        return "fresh_v8_repair"
    return "fresh_posthoc_repair"


def repaired_scaffold_summary_path(root: Path, split: str) -> Path:
    if split == "fresh-v8":
        return root / "scoring" / "fresh_v8_repair_scaffold" / "scaffold_generation_result.json"
    return root / "scoring" / "repair_to_poc_generated_scaffold_summary.json"


def repaired_scaffold_source_notes(candidate: dict[str, Any], manifest: dict[str, Any]) -> str:
    assertion_plan = candidate.get("assertion_plan") or {}
    assertions = as_list(candidate.get("assertion") or assertion_plan.get("assertions") or (candidate.get("minimal_poc_idea") or {}).get("assertions"))
    sequence = as_list(candidate.get("exploit_sequence") or (candidate.get("minimal_poc_idea") or {}).get("attack_steps"))
    lines = [
        "# Fresh-v8 Repaired Candidate Scaffold Source Notes",
        "",
        "This is a scaffold-only, post-hoc spent-holdout planning artifact. It is not executed evidence, not report-ready, and does not count toward readiness.",
        "",
        f"- Candidate: `{candidate.get('candidate_id') or manifest.get('candidate_id')}`",
        f"- Case: `{candidate.get('case_id')}`",
        f"- Target: `{candidate.get('file_path') or candidate.get('file')}::{candidate.get('contract')}.{candidate.get('function')}`",
        f"- Bug class: `{candidate.get('bug_class')}`",
        f"- Affected asset/state: {candidate.get('affected_asset') or 'manual validation required'}",
        f"- Scaffold directory: `{manifest.get('output_dir')}`",
        "",
        "## Exploit path to manually implement before any execution",
    ]
    for i, step in enumerate(sequence, start=1):
        lines.append(f"{i}. {step}")
    if not sequence:
        lines.append("- Manual exploit sequence is still required before execution.")
    lines.extend(["", "## Assertion plan"])
    for assertion in assertions:
        lines.append(f"- {assertion}")
    if not assertions:
        lines.append("- Manual concrete impact assertions are still required before execution.")
    lines.extend([
        "",
        "## Kill condition",
        f"- {candidate.get('kill_condition') or assertion_plan.get('kill_condition') or 'Kill if source/manual validation blocks reachability or impact.'}",
        "",
        "## Safety status",
        "- Execution approved: false",
        "- Executed: false",
        "- Network/fork/RPC use: false",
        "- Secrets/environment reads: false",
        "- Broadcasts: false",
        "- Dependency installation: false",
        "- Production source modification: false",
    ])
    return "\n".join(lines) + "\n"


def repaired_scaffold_preflight_plan(candidate: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "PASS",
        "mode": "fresh_v8_repair_scaffold_preflight",
        "candidate_id": manifest.get("candidate_id"),
        "case_id": candidate.get("case_id"),
        "split": candidate.get("split") or manifest.get("split"),
        "target": {
            "file_path": candidate.get("file_path") or candidate.get("file"),
            "contract": candidate.get("contract"),
            "function": candidate.get("function"),
        },
        "scaffold_only": True,
        "execution_approved": False,
        "executed": False,
        "counts_as_finding": False,
        "counts_toward_readiness": False,
        "production_readiness_changed": False,
        "requires_network": False,
        "requires_fork": False,
        "network_used": False,
        "broadcasts_used": False,
        "requires_secrets": False,
        "secrets_accessed": False,
        "reads_environment": False,
        "dependency_install_required": False,
        "dependency_install_allowed": False,
        "modifies_production_source": False,
        "execution_gate": {
            "approved": False,
            "approval_required_before_execution": True,
            "allowed_current_action": "generate scaffold and planning artifacts only",
            "blocked_actions": [
                "run forge tests for this scaffold",
                "fetch new repositories or alternate sources",
                "use RPC or fork state",
                "broadcast transactions",
                "read secrets or environment files",
                "install dependencies",
                "modify production source files",
            ],
        },
        "manual_completion_required": True,
        "manual_requirements": [
            "confirm exact source reachability and attacker privileges",
            "replace comments with local harness setup and concrete calls",
            "add exact state or balance assertions proving concrete impact",
            "run validation gate only after an explicitly approved execution task",
        ],
    }


def load_expected_aligned_candidate(root: Path) -> dict[str, Any]:
    payload = load_json(root / "scoring" / "fresh_v6_expected_aligned_repair" / "expected_related_candidate_selection.json", {})
    if payload.get("selected"):
        return payload.get("candidate") or {}
    return {}


def expected_aligned_contract_source(candidate: dict[str, Any]) -> str:
    contract_name = safe_id(f"ExpectedAligned_{candidate.get('candidate_id')}")
    minimal = candidate.get("minimal_poc_idea") or {}
    setup = minimal.get("setup") or {}
    steps = candidate.get("exploit_sequence") or minimal.get("attack_steps") or []
    assertions = minimal.get("assertions") or []
    comments = []
    comments.append("    // Actors: " + solidity_string(", ".join(minimal.get("actors") or [])))
    comments.append("    // Setup assumptions: " + solidity_string(json.dumps(setup, sort_keys=True)))
    for i, step in enumerate(steps[:10], start=1):
        comments.append(f"    // Attack step {i}: {solidity_string(step)}")
    for i, assertion in enumerate(assertions[:6], start=1):
        comments.append(f"    // Assertion {i}: {solidity_string(assertion)}")
    comments.append("    // Kill condition: " + solidity_string(candidate.get("kill_condition") or minimal.get("kill_condition")))
    comments.append("    // Missing dependencies: local harness/mocks must implement external integrations before execution.")
    comments.append("    // Preflight requirements: no network, no fork, no broadcasts, no production source modification.")
    body = "\n".join(comments)
    return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Scaffold only for post-hoc expected-aligned repair. Not executed in this task.
contract {contract_name} {{
    event ExpectedAlignedCandidate(string candidateId, string caseId, string expectedFindingId);

    function test_scaffold_documents_expected_aligned_repair() public {{
        emit ExpectedAlignedCandidate("{solidity_string(candidate.get('candidate_id'))}", "{solidity_string(candidate.get('case_id'))}", "{solidity_string(candidate.get('expected_finding_id'))}");
{body}
        bool executed = false;
        require(!executed, "scaffold-only expected-aligned repair task");
    }}
}}
"""


def generate_expected_aligned_scaffold(root: Path = PUBLIC_ROOT, *, split: str = "fresh-v6", scaffold_only: bool = True) -> dict[str, Any]:
    if not scaffold_only:
        result = {"status": "BLOCKED", "reason": "expected-aligned repair generation is scaffold-only in this task", "production_readiness_changed": False}
        (root / "scoring" / "fresh_v6_expected_aligned_repair" / "expected_related_scaffold_summary.json").parent.mkdir(parents=True, exist_ok=True)
        (root / "scoring" / "fresh_v6_expected_aligned_repair" / "expected_related_scaffold_summary.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    candidate = load_expected_aligned_candidate(root)
    if not candidate:
        result = {"status": "EXPECTED_RELATED_REPAIR_INCONCLUSIVE", "split": split, "reason": "no selected expected-aligned candidate", "generated_count": 0, "generated": [], "production_readiness_changed": False}
        out = root / "scoring" / "fresh_v6_expected_aligned_repair" / "expected_related_scaffold_summary.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2) + "\n")
        return result
    candidate_id = str(candidate.get("candidate_id"))
    out_dir = generated_root(root) / "fresh_v6_expected_aligned_repair" / safe_id(candidate_id)
    manifest = write_project(out_dir, expected_aligned_contract_source(candidate), {
        "poc_type": "fresh_v6_expected_aligned_repair_scaffold",
        "candidate_id": candidate_id,
        "hypothesis_id": candidate.get("hypothesis_id") or candidate.get("id"),
        "case_id": candidate.get("case_id"),
        "split": split,
        "expected_finding_id": candidate.get("expected_finding_id"),
        "expected_finding_related": True,
        "match_type_after_repair": load_json(root / "scoring" / "fresh_v6_expected_aligned_repair" / "expected_related_candidate_selection.json", {}).get("match_type_after_repair"),
        "source_case_path": f"{split}/{candidate.get('case_id')}",
        "file_path": candidate.get("file_path"),
        "contract": candidate.get("contract"),
        "function": candidate.get("function"),
        "bug_class": candidate.get("bug_class"),
        "affected_asset": candidate.get("affected_asset"),
        "output_dir": str(out_dir.relative_to(root)),
    }, post_hoc_regression_only=True)
    manifest.update({
        "execution_approved": False,
        "execution_block_reason": "scaffold-only expected-aligned repair task",
        "executed": False,
        "expected_aligned_repair_only": True,
        "counts_toward_readiness": False,
        "production_readiness_changed": False,
        "report_ready_created": False,
    })
    (out_dir / "poc_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    result = {"status": "PASS", "split": split, "mode": "expected_aligned_scaffold_only", "candidate_id": candidate_id, "generated_count": 1, "generated": [manifest], "output_dir": str(out_dir.relative_to(root)), "executed": False, "execution_approved": False, "reason": "scaffold-only expected-aligned repair task", "production_readiness_changed": False, "counts_toward_readiness": False}
    out = root / "scoring" / "fresh_v6_expected_aligned_repair" / "expected_related_scaffold_summary.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    return result


def expected_aligned_execution_dir(root: Path) -> Path:
    out = root / "scoring" / "fresh_v6_expected_aligned_execution"
    out.mkdir(parents=True, exist_ok=True)
    return out


def expected_aligned_manifest_path(root: Path, candidate_id: str) -> Path:
    return generated_root(root) / "fresh_v6_expected_aligned_repair" / safe_id(candidate_id) / "poc_manifest.json"


def expected_aligned_source_review(root: Path, *, split: str, candidate: dict[str, Any]) -> dict[str, Any]:
    case_id = str(candidate.get("case_id") or "")
    target_file = str(candidate.get("file_path") or candidate.get("file") or "")
    target_path = root / split / case_id / target_file
    target_text = target_path.read_text(errors="replace") if target_path.exists() else ""
    companion_rel = "src/token/wiTRY/crosschain/UnstakeMessenger.sol"
    parent_rel = "src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol"
    companion_path = root / split / case_id / companion_rel
    parent_path = root / split / case_id / parent_rel
    companion_text = companion_path.read_text(errors="replace") if companion_path.exists() else ""
    parent_text = parent_path.read_text(errors="replace") if parent_path.exists() else ""
    source_files = [target_file]
    if companion_path.exists():
        source_files.append(companion_rel)
    if parent_path.exists():
        source_files.append(parent_rel)
    blocks: list[str] = []
    required_fragments = ["unstakeThroughComposer", "amountLD: assets", "minAmountLD: assets", "_send(ASSET_OFT"]
    for fragment in required_fragments:
        if fragment not in target_text:
            blocks.append(f"missing source fragment: {fragment}")
    if "function unstake(" not in companion_text:
        blocks.append("normal spoke-chain unstake entrypoint not found")
    if "IOFT(_oft).send" not in parent_text:
        blocks.append("parent OFT send call not found")
    review = {
        "candidate_id": candidate.get("candidate_id") or candidate.get("id"),
        "case_id": case_id,
        "expected_finding_id": candidate.get("expected_finding_id"),
        "match_type_after_repair": load_json(root / "scoring" / "fresh_v6_expected_aligned_repair" / "expected_related_candidate_selection.json", {}).get("match_type_after_repair"),
        "target_file": target_file,
        "target_contract": candidate.get("contract"),
        "target_function": candidate.get("function"),
        "bug_class": candidate.get("bug_class"),
        "source_files_reviewed": source_files,
        "relevant_state_variables": ["VAULT", "ASSET_OFT", "ASSET_ERC20", "VAULT_EID"],
        "relevant_external_calls": [
            "IStakediTryCrosschain(address(VAULT)).unstakeThroughComposer(user)",
            "_send(ASSET_OFT, _sendParam, address(this))",
            "IOFT(_oft).send(_sendParam, MessagingFee(msg.value, 0), _refundAddress)",
        ],
        "relevant_asset_flows": [
            "completed cooldown assets are pulled from the vault through unstakeThroughComposer(user)",
            "assets is copied into SendParam.amountLD",
            "the same assets value is copied into SendParam.minAmountLD",
            "the ASSET_OFT adapter performs the hub-to-spoke return transfer",
        ],
        "relevant_lifecycle": [
            "user calls UnstakeMessenger.unstake(returnTripAllocation) on the spoke chain",
            "UnstakeMessenger encodes msg.sender into UnstakeMessage.user and sends MSG_TYPE_UNSTAKE",
            "wiTryVaultComposer._lzReceive routes MSG_TYPE_UNSTAKE to _handleUnstake",
            "_handleUnstake calls unstakeThroughComposer and sends assets back through ASSET_OFT",
        ],
        "normal_victim_or_user_action": "normal user requests cross-chain unstake from the spoke chain after completing cooldown on the hub-side vault",
        "expected_vulnerable_behavior": "for a dust-containing assets amount, _handleUnstake sets minAmountLD equal to amountLD; an OFT adapter that removes decimal dust can debit/deliver less than minAmountLD and revert the return leg",
        "expected_kill_condition": candidate.get("kill_condition") or (candidate.get("minimal_poc_idea") or {}).get("kill_condition"),
        "source_review_blocks": blocks,
        "answer_key_text_dependency": False,
        "network_used": False,
        "secrets_accessed": False,
        "broadcasts_used": False,
        "dependency_install_attempted": False,
        "production_source_modified": False,
        "counts_toward_readiness": False,
    }
    out_dir = expected_aligned_execution_dir(root)
    (out_dir / "expected_aligned_source_review.json").write_text(json.dumps(review, indent=2) + "\n")
    md = [
        "# Expected-Aligned Source Review",
        "",
        f"- Candidate: {review['candidate_id']}",
        f"- Case: {case_id}",
        f"- Target: {target_file}:{review.get('target_contract')}.{review.get('target_function')}",
        f"- Source files reviewed: {', '.join(source_files)}",
        f"- Normal action: {review['normal_victim_or_user_action']}",
        f"- Expected vulnerable behavior: {review['expected_vulnerable_behavior']}",
        f"- Kill condition: {review['expected_kill_condition']}",
        f"- Blocks: {', '.join(blocks) if blocks else 'none'}",
        "- Answer-key text dependency: false",
    ]
    (out_dir / "expected_aligned_source_review.md").write_text("\n".join(md) + "\n")
    return review


def expected_aligned_filled_contract_source(candidate: dict[str, Any]) -> str:
    candidate_id = solidity_string(candidate.get("candidate_id") or candidate.get("id"))
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Local-only harness for an expected-aligned spent-holdout repair.
/// It models only the source-reviewed _handleUnstake return-leg invariant:
/// amountLD and minAmountLD are both set to the nominal assets amount before
/// an OFT-style adapter removes decimal dust. No production source is imported
/// or modified, and no network/fork/broadcast is used.

contract ExpectedAlignedDustOFT {{
    error SlippageExceeded(uint256 deliveredLD, uint256 minAmountLD);

    struct SendParam {{
        uint32 dstEid;
        bytes32 to;
        uint256 amountLD;
        uint256 minAmountLD;
        bytes extraOptions;
        bytes composeMsg;
        bytes oftCmd;
    }}

    uint256 public immutable dustRate;
    uint256 public lastDeliveredLD;
    uint256 public lastMinAmountLD;

    constructor(uint256 _dustRate) {{
        dustRate = _dustRate;
    }}

    function previewDelivered(uint256 amountLD) public view returns (uint256) {{
        return amountLD - (amountLD % dustRate);
    }}

    function send(SendParam memory p) external returns (uint256 deliveredLD) {{
        deliveredLD = previewDelivered(p.amountLD);
        lastDeliveredLD = deliveredLD;
        lastMinAmountLD = p.minAmountLD;
        if (deliveredLD < p.minAmountLD) revert SlippageExceeded(deliveredLD, p.minAmountLD);
    }}
}}

contract ExpectedAlignedUnstakeHarness {{
    error InvalidZeroAddress();
    error InvalidOrigin();
    error NoAssetsToUnstake();

    ExpectedAlignedDustOFT public immutable assetOft;
    bool public returnLegProcessed;
    address public lastUser;
    uint32 public lastSourceEid;
    uint256 public lastAssets;

    constructor(ExpectedAlignedDustOFT _assetOft) {{
        assetOft = _assetOft;
    }}

    function handleUnstakeVulnerable(address user, uint32 srcEid, uint256 assets) external {{
        if (user == address(0)) revert InvalidZeroAddress();
        if (srcEid == 0) revert InvalidOrigin();
        if (assets == 0) revert NoAssetsToUnstake();

        // Mirrors wiTryVaultComposer._handleUnstake:264-272.
        ExpectedAlignedDustOFT.SendParam memory p = ExpectedAlignedDustOFT.SendParam({{
            dstEid: srcEid,
            to: bytes32(uint256(uint160(user))),
            amountLD: assets,
            minAmountLD: assets,
            extraOptions: "",
            composeMsg: "",
            oftCmd: ""
        }});
        assetOft.send(p);

        returnLegProcessed = true;
        lastUser = user;
        lastSourceEid = srcEid;
        lastAssets = assets;
    }}

    function handleUnstakePatchedLowerMinimum(address user, uint32 srcEid, uint256 assets) external {{
        if (user == address(0)) revert InvalidZeroAddress();
        if (srcEid == 0) revert InvalidOrigin();
        if (assets == 0) revert NoAssetsToUnstake();
        uint256 deliverable = assets - (assets % assetOft.dustRate());
        ExpectedAlignedDustOFT.SendParam memory p = ExpectedAlignedDustOFT.SendParam({{
            dstEid: srcEid,
            to: bytes32(uint256(uint160(user))),
            amountLD: assets,
            minAmountLD: deliverable,
            extraOptions: "",
            composeMsg: "",
            oftCmd: ""
        }});
        assetOft.send(p);
        returnLegProcessed = true;
        lastUser = user;
        lastSourceEid = srcEid;
        lastAssets = assets;
    }}
}}

contract ExpectedAligned_EXECUTABLE_contest_4001_M_02 {{
    event ExpectedAlignedCandidate(string candidateId, string assertion);

    function test_expectedAligned_control_dustFreeAmountProcesses() public {{
        ExpectedAlignedDustOFT oft = new ExpectedAlignedDustOFT(1000);
        ExpectedAlignedUnstakeHarness composer = new ExpectedAlignedUnstakeHarness(oft);
        address victim = address(0xBEEF);

        composer.handleUnstakeVulnerable(victim, 101, 5000);

        require(composer.returnLegProcessed(), "dust-free control should process");
        require(oft.lastDeliveredLD() == 5000, "dust-free delivered amount mismatch");
        require(oft.lastMinAmountLD() == 5000, "dust-free minimum mismatch");
    }}

    function test_expectedAligned_control_loweredMinimumProcessesDustAmount() public {{
        ExpectedAlignedDustOFT oft = new ExpectedAlignedDustOFT(1000);
        ExpectedAlignedUnstakeHarness composer = new ExpectedAlignedUnstakeHarness(oft);
        address victim = address(0xBEEF);

        composer.handleUnstakePatchedLowerMinimum(victim, 101, 5001);

        require(composer.returnLegProcessed(), "lowered minimum should process dust amount");
        require(oft.lastDeliveredLD() == 5000, "patched deliverable amount mismatch");
        require(oft.lastMinAmountLD() == 5000, "patched minimum mismatch");
    }}

    function test_expectedAligned_dustAmountRevertsAndFreezesExit() public {{
        emit ExpectedAlignedCandidate("{candidate_id}", "fund_freeze when minAmountLD equals dust-containing amountLD");
        ExpectedAlignedDustOFT oft = new ExpectedAlignedDustOFT(1000);
        ExpectedAlignedUnstakeHarness composer = new ExpectedAlignedUnstakeHarness(oft);
        address victim = address(0xBEEF);
        require(oft.previewDelivered(5001) == 5000, "dust preview should be below nominal");

        bool succeeded;
        try composer.handleUnstakeVulnerable(victim, 101, 5001) {{
            succeeded = true;
        }} catch {{
            succeeded = false;
        }}

        require(!succeeded, "kill: vulnerable return leg unexpectedly succeeded for dust amount");
        require(!composer.returnLegProcessed(), "fund-freeze assertion: normal exit must remain unprocessed");
    }}
}}
'''


def fill_expected_aligned_candidate_vertical_slice(root: Path = PUBLIC_ROOT, *, split: str = "fresh-v6", candidate_id: str) -> dict[str, Any]:
    selection = load_json(root / "scoring" / "fresh_v6_expected_aligned_repair" / "expected_related_candidate_selection.json", {})
    candidate = selection.get("candidate") or {}
    if candidate_id and candidate.get("candidate_id") != candidate_id:
        result = {"status": "BLOCKED", "candidate_id": candidate_id, "reason": "expected-aligned candidate selection missing", "production_readiness_changed": False, "counts_toward_readiness": False}
        expected_aligned_execution_dir(root).joinpath("expected_aligned_fill_result.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    if not candidate:
        result = {"status": "BLOCKED", "candidate_id": candidate_id, "reason": "no selected expected-aligned candidate", "production_readiness_changed": False, "counts_toward_readiness": False}
        expected_aligned_execution_dir(root).joinpath("expected_aligned_fill_result.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    manifest_path = expected_aligned_manifest_path(root, candidate_id)
    if not manifest_path.exists():
        scaffold = generate_expected_aligned_scaffold(root, split=split, scaffold_only=True)
        if scaffold.get("status") != "PASS":
            result = {"status": "BLOCKED", "candidate_id": candidate_id, "reason": "expected-aligned scaffold missing", "scaffold": scaffold, "production_readiness_changed": False, "counts_toward_readiness": False}
            expected_aligned_execution_dir(root).joinpath("expected_aligned_fill_result.json").write_text(json.dumps(result, indent=2) + "\n")
            return result
    review = expected_aligned_source_review(root, split=split, candidate=candidate)
    if review.get("source_review_blocks"):
        result = {"status": "BLOCKED", "candidate_id": candidate_id, "reason": "source review blocked scaffold fill", "source_review": review, "production_readiness_changed": False, "counts_toward_readiness": False}
        expected_aligned_execution_dir(root).joinpath("expected_aligned_fill_result.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    manifest = load_json(manifest_path, {})
    test_path = manifest_path.parent / "test" / "GeneratedPoC.t.sol"
    test_path.write_text(expected_aligned_filled_contract_source(candidate))
    manifest.update({
        "status": "PASS",
        "manual_fill_completed": True,
        "expected_aligned_manual_fill_completed": True,
        "scaffold_only": False,
        "execution_approved": True,
        "execution_block_reason": "",
        "command": "forge test --match-test test_expectedAligned_dustAmountRevertsAndFreezesExit -vvv",
        "test_name": "test_expectedAligned_dustAmountRevertsAndFreezesExit",
        "assertion": "dust-containing normal cross-chain unstake return leg reverts and leaves the exit unprocessed when minAmountLD equals amountLD",
        "kill_condition": "kill if the modeled OFT send does not remove dust, if minAmountLD is adjusted below the nominal amount, or if the dust-containing normal action succeeds",
        "normal_user_path": "user calls UnstakeMessenger.unstake after cooldown; LayerZero routes MSG_TYPE_UNSTAKE to wiTryVaultComposer._handleUnstake",
        "victim_or_protocol_action": "wiTryVaultComposer attempts to return unstaked assets through ASSET_OFT",
        "attack_or_failure_condition": "assets amount has decimal dust and ASSET_OFT removes dust before checking minAmountLD",
        "same_attack_steps_used": True,
        "source_review": "scoring/fresh_v6_expected_aligned_execution/expected_aligned_source_review.json",
        "executed": False,
        "report_ready": False,
        "counts_as_finding": False,
        "counts_toward_readiness": False,
        "production_readiness_changed": False,
        "report_ready_created": False,
    })
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    result = {"status": "PASS", "candidate_id": candidate_id, "test_file": str(test_path.relative_to(root)), "manifest": str(manifest_path.relative_to(root)), "source_review": "scoring/fresh_v6_expected_aligned_execution/expected_aligned_source_review.json", "production_readiness_changed": False, "counts_toward_readiness": False}
    expected_aligned_execution_dir(root).joinpath("expected_aligned_fill_result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def generate_repaired_candidate_scaffold(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation", candidate_id: str, scaffold_only: bool = True) -> dict[str, Any]:
    summary_path = repaired_scaffold_summary_path(root, split)
    if not scaffold_only:
        result = {
            "status": "BLOCKED",
            "reason": "only scaffold-only generation is allowed for repaired fresh holdout candidates",
            "candidate_id": candidate_id,
            "split": split,
            "scaffold_only": False,
            "execution_approved": False,
            "production_readiness_changed": False,
            "counts_toward_readiness": False,
        }
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(json.dumps(result, indent=2) + "\n")
        return result
    candidate = load_repaired_candidate(root, candidate_id, split=split)
    if not candidate:
        result = {
            "status": "BLOCKED",
            "reason": "repaired candidate was not selected or enriched",
            "candidate_id": candidate_id,
            "split": split,
            "generated_count": 0,
            "generated": [],
            "scaffold_only": True,
            "execution_approved": False,
            "production_readiness_changed": False,
            "report_ready_created": False,
            "counts_toward_readiness": False,
        }
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(json.dumps(result, indent=2) + "\n")
        return result
    resolved_id = str(candidate.get("candidate_id") or candidate_id)
    out_dir = generated_root(root) / repaired_scaffold_output_subdir(split) / resolved_id
    assertion_plan = candidate.get("assertion_plan") or {}
    manifest = write_project(out_dir, candidate_contract_source(candidate), {
        "poc_type": "fresh_v8_repair_scaffold" if split == "fresh-v8" else "fresh_posthoc_repair_scaffold",
        "candidate_id": resolved_id,
        "repaired_candidate_id": str(candidate.get("repaired_candidate_id") or resolved_id),
        "hypothesis_id": candidate.get("hypothesis_id"),
        "case_id": candidate.get("case_id"),
        "split": split,
        "source_case_path": candidate.get("source_case_path") or f"{split}/{candidate.get('case_id')}",
        "file_path": candidate.get("file_path") or candidate.get("file"),
        "contract": candidate.get("contract"),
        "function": candidate.get("function"),
        "bug_class": candidate.get("bug_class"),
        "affected_asset": candidate.get("affected_asset"),
        "attacker_capability": candidate.get("attacker_capability"),
        "quality_score": candidate.get("quality_score"),
        "match_type": candidate.get("match_type"),
        "expected_finding_related": candidate.get("expected_finding_related"),
        "assertion": candidate.get("assertion") or assertion_plan.get("assertions"),
        "assertion_plan": assertion_plan,
        "kill_condition": candidate.get("kill_condition") or assertion_plan.get("kill_condition"),
        "exploit_sequence": candidate.get("exploit_sequence") or (candidate.get("minimal_poc_idea") or {}).get("attack_steps"),
        "preconditions": candidate.get("preconditions"),
        "state_setup": candidate.get("state_setup"),
        "minimal_poc_idea": candidate.get("minimal_poc_idea"),
        "post_hoc_repair_only": True,
        "post_hoc_spent_holdout": split == "fresh-v8",
        "fresh_independent_holdout": False,
        "output_dir": str(out_dir.relative_to(root)),
    }, post_hoc_regression_only=False)
    manifest.update({
        "post_hoc_repair_only": True,
        "post_hoc_spent_holdout": split == "fresh-v8",
        "fresh_independent_holdout": False,
        "executed": False,
        "execution_approved": False,
        "scaffold_only": True,
        "counts_as_finding": False,
        "counts_toward_readiness": False,
        "report_ready": False,
        "report_ready_created": False,
        "production_readiness_changed": False,
    })
    (out_dir / "poc_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    source_notes_path = None
    preflight_path = None
    if split == "fresh-v8":
        scaffold_scoring_dir = summary_path.parent
        scaffold_scoring_dir.mkdir(parents=True, exist_ok=True)
        source_notes_path = scaffold_scoring_dir / "scaffold_source_notes.md"
        source_notes_path.write_text(repaired_scaffold_source_notes(candidate, manifest))
        preflight_path = scaffold_scoring_dir / "scaffold_preflight_plan.json"
        preflight_path.write_text(json.dumps(repaired_scaffold_preflight_plan(candidate, manifest), indent=2) + "\n")
    result = {
        "status": "PASS",
        "mode": "fresh_v8_repair_scaffold_only" if split == "fresh-v8" else "fresh_posthoc_repair_scaffold_only",
        "split": split,
        "candidate_id": resolved_id,
        "generated_count": 1,
        "generated": [manifest],
        "output_dir": str(out_dir.relative_to(root)),
        "manifest": str((out_dir / "poc_manifest.json").relative_to(root)),
        "source_notes": str(source_notes_path.relative_to(root)) if source_notes_path else "",
        "preflight_plan": str(preflight_path.relative_to(root)) if preflight_path else "",
        "scaffold_only": True,
        "execution_approved": False,
        "executed": False,
        "report_ready_created": False,
        "counts_as_finding": False,
        "production_readiness_changed": False,
        "counts_toward_readiness": False,
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(result, indent=2) + "\n")
    if split == "fresh-v8":
        legacy = root / "scoring" / "repair_to_poc_generated_scaffold_summary.json"
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text(json.dumps(result, indent=2) + "\n")
    return result


def _source_text(path: Path) -> str:
    return path.read_text(errors="replace") if path.exists() else ""


def repair_candidate_source_review(root: Path = PUBLIC_ROOT, *, candidate_id: str, split: str = "fresh-confirmation") -> dict[str, Any]:
    candidate = load_repaired_candidate(root, candidate_id, split=split)
    target_file = str(candidate.get("file_path") or "contracts/capital-protocol/Distributor.sol")
    case_id = str(candidate.get("case_id") or "contest_3003")
    source_root = root / split / case_id
    target_path = source_root / target_file
    supporting = [
        source_root / "contracts/interfaces/capital-protocol/IDistributor.sol",
        source_root / "contracts/capital-protocol/DepositPool.sol",
    ]
    reviewed_paths = [target_path] + [p for p in supporting if p.exists()]
    target_text = _source_text(target_path)
    blocks: list[str] = []
    if not target_text:
        blocks.append("target source file missing from local frozen artifacts")
    if "function supply" not in target_text:
        blocks.append("target function supply not found in reviewed source")
    if "safeTransferFrom" not in target_text or "deposited += amount_" not in target_text:
        blocks.append("source does not contain the expected transfer-then-record accounting pattern")
    relevant_state = [name for name in ["depositPools", "distributedRewards", "rewardPoolLastCalculatedTimestamp", "undistributedRewards"] if name in target_text]
    relevant_calls = [
        call
        for call in [
            "distributeRewards(rewardPoolIndex_)",
            "_withdrawYield(rewardPoolIndex_, depositPoolAddress_)",
            "IERC20(depositPool.token).safeTransferFrom(depositPoolAddress_, address(this), amount_)",
            "AaveIPool(aavePool).supply(depositPool.token, amount_, address(this), 0)",
        ]
        if call.split("(")[0] in target_text or "safeTransferFrom" in call and "safeTransferFrom" in target_text
    ]
    asset_flows = []
    if "safeTransferFrom(depositPoolAddress_, address(this), amount_)" in target_text:
        asset_flows.append("deposit token moves from DepositPool/msg.sender to Distributor using amount_ rather than a measured balance delta")
    if "depositPool.deposited += amount_" in target_text:
        asset_flows.append("Distributor records depositPool.deposited += amount_")
    if "depositPool.lastUnderlyingBalance += amount_" in target_text:
        asset_flows.append("Distributor records depositPool.lastUnderlyingBalance += amount_")
    lifecycle = []
    deposit_pool_text = "\n".join(_source_text(p) for p in supporting if p.exists())
    if "IDistributor(distributor).supply(rewardPoolIndex_, amount_)" in deposit_pool_text:
        lifecycle.append("DepositPool._stake transfers user tokens to DepositPool, measures received amount, then calls Distributor.supply")
    if "IDistributor(distributor).withdraw(rewardPoolIndex_, amount_)" in deposit_pool_text:
        lifecycle.append("DepositPool._withdraw later calls Distributor.withdraw and expects the recorded amount to be withdrawable")
    expected = ""
    kill = ""
    if not blocks:
        expected = (
            "Distributor.supply records amount_ in deposited and lastUnderlyingBalance after safeTransferFrom "
            "without measuring the Distributor token balance delta. If the actual amount received by Distributor "
            "is lower than amount_, recorded accounting exceeds the token balance and a later withdrawal of the recorded amount reverts/fund-freezes."
        )
        kill = (
            "Kill if the local supply path measures the actual received amount, if recorded accounting equals actual token balance "
            "after the boundary transfer, or if withdrawal of the recorded amount succeeds without an accounting/balance mismatch."
        )
    review = {
        "candidate_id": candidate_id,
        "case_id": case_id,
        "target_file": target_file,
        "target_contract": str(candidate.get("contract") or "Distributor"),
        "target_function": str(candidate.get("function") or "supply"),
        "bug_class": str(candidate.get("bug_class") or "accounting-desync"),
        "source_files_reviewed": [str(p.relative_to(source_root)) for p in reviewed_paths if p.exists()],
        "relevant_state_variables": relevant_state,
        "relevant_external_calls": relevant_calls,
        "relevant_asset_flows": asset_flows,
        "relevant_lifecycle": lifecycle,
        "expected_vulnerable_behavior": expected,
        "expected_kill_condition": kill,
        "source_review_blocks": blocks,
        "answer_key_dependency": False,
    }
    out_dir = repaired_execution_dir(root)
    (out_dir / "repair_candidate_source_review.json").write_text(json.dumps(review, indent=2) + "\n")
    md = [
        "# Repaired Candidate Source Review",
        "",
        f"- Candidate: `{candidate_id}`",
        f"- Case: `{case_id}`",
        f"- Target: `{target_file}::{review['target_contract']}.{review['target_function']}`",
        f"- Bug class: `{review['bug_class']}`",
        "",
        "## Files reviewed",
        *(f"- `{path}`" for path in review["source_files_reviewed"]),
        "",
        "## Relevant state",
        *(f"- `{name}`" for name in relevant_state),
        "",
        "## Relevant calls and flows",
        *(f"- {item}" for item in relevant_calls + asset_flows + lifecycle),
        "",
        "## Expected vulnerable behavior",
        expected or "Blocked: source review did not establish a concrete local assertion target.",
        "",
        "## Expected kill condition",
        kill or "Blocked before execution.",
        "",
        "## Blocks",
        *(f"- {block}" for block in blocks),
    ]
    (out_dir / "repair_candidate_source_review.md").write_text("\n".join(md) + "\n")
    return review


def repaired_candidate_filled_source() -> str:
    return r'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Local-only harness for a repaired post-hoc accounting candidate.
/// @dev Mirrors only the Distributor.supply accounting order needed for the post-hoc vertical slice.
contract FeeOnTransferToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public immutable feeBps;

    constructor(uint256 feeBps_) { feeBps = feeBps_; }

    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "allowance");
        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "insufficient-balance");
        balanceOf[from] -= amount;
        uint256 received = amount - ((amount * feeBps) / 10_000);
        balanceOf[to] += received;
        // The fee is burned to make the received amount smaller than amount_.
    }
}

contract DistributorSupplyHarness {
    struct DepositPoolState {
        address token;
        uint256 deposited;
        uint256 lastUnderlyingBalance;
        bool isExist;
    }

    mapping(uint256 => mapping(address => DepositPoolState)) public depositPools;
    address public l1Sender = address(0xBEEF);

    function addDepositPool(uint256 rewardPoolIndex, address depositPool, address token) external {
        depositPools[rewardPoolIndex][depositPool] = DepositPoolState({
            token: token,
            deposited: 0,
            lastUnderlyingBalance: 0,
            isExist: true
        });
    }

    function supply(uint256 rewardPoolIndex, uint256 amount) external {
        address depositPoolAddress = msg.sender;
        DepositPoolState storage depositPool = depositPools[rewardPoolIndex][depositPoolAddress];
        require(depositPool.isExist, "DR: deposit pool doesn't exist");

        _withdrawYield(rewardPoolIndex, depositPoolAddress);

        // Mirrors Distributor.sol:295. The production code does not measure balanceBefore/balanceAfter here.
        FeeOnTransferToken(depositPool.token).transferFrom(depositPoolAddress, address(this), amount);

        // Mirrors Distributor.sol:300-301. This records amount even when actual received is lower.
        depositPool.deposited += amount;
        depositPool.lastUnderlyingBalance += amount;
    }

    function withdraw(uint256 rewardPoolIndex, uint256 amount) external returns (uint256) {
        address depositPoolAddress = msg.sender;
        DepositPoolState storage depositPool = depositPools[rewardPoolIndex][depositPoolAddress];
        require(depositPool.isExist, "DR: deposit pool doesn't exist");
        if (amount > depositPool.deposited) amount = depositPool.deposited;
        require(amount > 0, "DR: nothing to withdraw");
        depositPool.deposited -= amount;
        depositPool.lastUnderlyingBalance -= amount;
        _withdrawYield(rewardPoolIndex, depositPoolAddress);
        FeeOnTransferToken(depositPool.token).transfer(depositPoolAddress, amount);
        return amount;
    }

    function poolState(uint256 rewardPoolIndex, address depositPool) external view returns (uint256 deposited, uint256 lastUnderlyingBalance) {
        DepositPoolState storage state = depositPools[rewardPoolIndex][depositPool];
        return (state.deposited, state.lastUnderlyingBalance);
    }

    function _withdrawYield(uint256 rewardPoolIndex, address depositPoolAddress) internal {
        DepositPoolState storage depositPool = depositPools[rewardPoolIndex][depositPoolAddress];
        uint256 yield = depositPool.lastUnderlyingBalance - depositPool.deposited;
        if (yield == 0) return;
        FeeOnTransferToken(depositPool.token).transfer(l1Sender, yield);
        depositPool.lastUnderlyingBalance -= yield;
    }
}

contract GeneratedPoC {
    uint256 constant REWARD_POOL_INDEX = 1;
    uint256 constant SUPPLY_AMOUNT = 100 ether;

    function test_control_standardTokenSupplyKeepsAccountingSynced() public {
        FeeOnTransferToken token = new FeeOnTransferToken(0);
        DistributorSupplyHarness distributor = new DistributorSupplyHarness();
        distributor.addDepositPool(REWARD_POOL_INDEX, address(this), address(token));
        token.mint(address(this), SUPPLY_AMOUNT);
        token.approve(address(distributor), SUPPLY_AMOUNT);

        distributor.supply(REWARD_POOL_INDEX, SUPPLY_AMOUNT);
        (uint256 deposited, uint256 lastUnderlyingBalance) = distributor.poolState(REWARD_POOL_INDEX, address(this));

        require(token.balanceOf(address(distributor)) == SUPPLY_AMOUNT, "control: actual balance mismatch");
        require(deposited == SUPPLY_AMOUNT, "control: deposited mismatch");
        require(lastUnderlyingBalance == SUPPLY_AMOUNT, "control: underlying mismatch");
    }

    function test_repairedCandidate_feeOnTransferSupplyCreatesAccountingDesync() public {
        // Setup: a deposit-pool actor supplies a token whose transferFrom returns less than amount_.
        FeeOnTransferToken token = new FeeOnTransferToken(1_000); // 10% burn on transfer.
        DistributorSupplyHarness distributor = new DistributorSupplyHarness();
        distributor.addDepositPool(REWARD_POOL_INDEX, address(this), address(token));
        token.mint(address(this), SUPPLY_AMOUNT);
        token.approve(address(distributor), SUPPLY_AMOUNT);

        // Attack/boundary: execute Distributor.supply's transfer-then-record path.
        distributor.supply(REWARD_POOL_INDEX, SUPPLY_AMOUNT);
        (uint256 deposited, uint256 lastUnderlyingBalance) = distributor.poolState(REWARD_POOL_INDEX, address(this));
        uint256 actualDistributorBalance = token.balanceOf(address(distributor));

        // Concrete assertion: recorded accounting exceeds actual token balance.
        require(actualDistributorBalance == 90 ether, "boundary did not reduce received amount");
        require(deposited == SUPPLY_AMOUNT, "deposited should record amount_ from supply");
        require(lastUnderlyingBalance == SUPPLY_AMOUNT, "lastUnderlyingBalance should record amount_ from supply");
        require(deposited > actualDistributorBalance, "kill: no accounting violation");

        // Impact assertion: withdrawing the recorded amount is impossible with the actual balance.
        (bool withdrawOk,) = address(distributor).call(
            abi.encodeWithSelector(DistributorSupplyHarness.withdraw.selector, REWARD_POOL_INDEX, SUPPLY_AMOUNT)
        );
        require(!withdrawOk, "kill: recorded amount remained withdrawable");
    }
}
'''


def fill_repaired_candidate_vertical_slice(root: Path = PUBLIC_ROOT, *, split: str = "fresh-confirmation", candidate_id: str) -> dict[str, Any]:
    scaffold = generate_repaired_candidate_scaffold(root, split=split, candidate_id=candidate_id, scaffold_only=True)
    if scaffold.get("status") != "PASS":
        return scaffold
    review = repair_candidate_source_review(root, candidate_id=candidate_id, split=split)
    out_dir = root / str(scaffold.get("output_dir"))
    if review.get("source_review_blocks"):
        manifest_path = out_dir / "poc_manifest.json"
        manifest = load_json(manifest_path, {})
        manifest.update({
            "manual_fill_completed": False,
            "scaffold_only": True,
            "execution_approved": False,
            "execution_block_reason": "source_review_blocked",
            "source_review_blocks": review.get("source_review_blocks"),
        })
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        result = {"status": "BLOCKED", "candidate_id": candidate_id, "reason": "source review blocked scaffold fill", "source_review": review, "production_readiness_changed": False}
        repaired_execution_dir(root).joinpath("repair_candidate_fill_result.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    (out_dir / "foundry.toml").write_text(vertical_slice_foundry_toml())
    test_path = out_dir / "test" / "GeneratedPoC.t.sol"
    test_path.parent.mkdir(parents=True, exist_ok=True)
    test_path.write_text(repaired_candidate_filled_source())
    test_name = "test_repairedCandidate_feeOnTransferSupplyCreatesAccountingDesync"
    manifest_path = out_dir / "poc_manifest.json"
    manifest = load_json(manifest_path, {})
    manifest.update({
        "poc_type": "fresh_posthoc_repair_filled_poc",
        "manual_fill_completed": True,
        "scaffold_only": False,
        "execution_approved": True,
        "execution_block_reason": "",
        "command": f"forge test --root . --match-test {test_name} -vvv",
        "test_name": test_name,
        "assertion": "recorded deposited/lastUnderlyingBalance exceeds actual token balance after supply; withdrawing recorded amount reverts/fund-freezes",
        "kill_condition": review.get("expected_kill_condition"),
        "same_attack_steps_used": True,
        "requires_network": False,
        "requires_fork": False,
        "broadcasts_used": False,
        "reads_environment": False,
        "modifies_production_source": False,
        "source_review": "scoring/repaired_candidate_execution/repair_candidate_source_review.json",
        "report_ready": False,
        "counts_as_finding": False,
        "counts_toward_readiness": False,
    })
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    result = {
        "status": "PASS",
        "candidate_id": candidate_id,
        "output_dir": str(out_dir.relative_to(root)),
        "test_file": str(test_path.relative_to(root)),
        "test_name": test_name,
        "source_review": "scoring/repaired_candidate_execution/repair_candidate_source_review.json",
        "scaffold_filled": True,
        "production_source_modified": False,
        "report_ready_created": False,
        "production_readiness_changed": False,
        "counts_toward_readiness": False,
    }
    repaired_execution_dir(root).joinpath("repair_candidate_fill_result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def fill_manual_vertical_slice(root: Path = PUBLIC_ROOT, *, candidate_id: str) -> dict[str, Any]:
    selection = load_vertical_selection(root)
    batch_candidate = load_candidate_from_batch(root, candidate_id)
    if selection.get("selected_candidate_id") != candidate_id and not batch_candidate.get("pair_id"):
        return {"status": "BLOCKED", "reason": "candidate is not the selected vertical-slice candidate", "candidate_id": candidate_id}
    candidate_manifest = find_candidate_manifest(root, candidate_id)
    if not candidate_manifest:
        return {"status": "BLOCKED", "reason": "generated candidate scaffold not found", "candidate_id": candidate_id}
    manifest = load_json(candidate_manifest)
    selected_data = batch_candidate if batch_candidate.get("pair_id") else selection
    candidate = {**selected_data, "candidate_id": candidate_id, "case_id": manifest.get("case_id"), "file_path": selected_data.get("file_path") or selected_data.get("file"), "source_case_path": manifest.get("source_case_path")}
    out_dir = candidate_manifest.parent
    (out_dir / "foundry.toml").write_text(vertical_slice_foundry_toml())
    test_path = out_dir / "test" / "GeneratedPoC.t.sol"
    test_path.parent.mkdir(parents=True, exist_ok=True)
    source, test_name, purpose = source_for_candidate(candidate_id)
    test_path.write_text(source)
    manifest.update({
        "poc_type": "vertical_slice_filled_poc",
        "candidate_id": candidate_id,
        "pair_id": selected_data.get("pair_id"),
        "command": f"forge test --root . --match-test {test_name} -vvv",
        "generated_files": ["foundry.toml", "test/GeneratedPoC.t.sol"],
        "scaffold_only": False,
        "execution_approved": True,
        "execution_block_reason": "",
        "requires_network": False,
        "requires_fork": False,
        "broadcasts_used": False,
        "reads_environment": False,
        "modifies_production_source": False,
        "manual_fill_completed": True,
        "vulnerable_test_name": test_name,
        "patched_test_name": test_name,
        "same_attack_steps_used": True,
        "assertion": selected_data.get("assertion_plan") or selected_data.get("assertion"),
        "kill_condition": selected_data.get("kill_condition"),
        "purpose": purpose,
        "report_ready": False,
        "counts_as_finding": False,
    })
    candidate_manifest.write_text(json.dumps(manifest, indent=2) + "\n")
    notes_path = write_source_notes(root, candidate, out_dir, candidate_id=candidate_id)
    result = {
        "status": "PASS",
        "candidate_id": candidate_id,
        "pair_id": selection.get("pair_id"),
        "output_dir": str(out_dir.relative_to(root)),
        "test_file": str(test_path.relative_to(root)),
        "source_notes": str(notes_path.relative_to(root)),
        "scaffold_filled": True,
        "production_source_modified": False,
        "report_ready_created": False,
        "production_readiness_changed": False,
    }
    (root / "scoring" / "poc_vertical_slice_fill_result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def fill_batch_vertical_slices(root: Path = PUBLIC_ROOT) -> dict[str, Any]:
    batch = load_json(root / "scoring" / "poc_vertical_slice_batch_selection.json", {})
    rows = []
    for candidate in batch.get("selected_candidates", []):
        rows.append(fill_manual_vertical_slice(root, candidate_id=candidate["candidate_id"]))
    result = {"status": "PASS" if rows and all(r.get("status") == "PASS" for r in rows) else "BLOCKED", "filled_count": sum(1 for r in rows if r.get("status") == "PASS"), "results": rows, "production_readiness_changed": False}
    (root / "scoring" / "poc_vertical_slice_batch_fill_result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def generate_from_selected_candidates(root: Path = PUBLIC_ROOT, *, split: str = "patched-controls") -> dict[str, Any]:
    selection_path = precision_dir(root) / "poc_candidate_selection.json" if split == "patched-controls" else split_selection_path(root, split)
    selection = load_json(selection_path, {"status": "MISSING", "candidates": []})
    generated = []
    if selection.get("status") == "MISSING" or not selection.get("candidates"):
        result = {"status": "BLOCKED", "split": split, "mode": "selected-candidates", "reason": "no selected PoC candidates", "generated_count": 0, "generated": [], "production_readiness_changed": False}
        summary_dir = precision_dir(root) if split == "patched-controls" else root / "scoring"
        summary_dir.mkdir(parents=True, exist_ok=True)
        summary_dir.joinpath("generated_poc_summary.json" if split == "patched-controls" else f"{split.replace('-', '_')}_generated_poc_summary.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    for candidate in selection.get("selected_candidates") or selection.get("candidates", []):
        out_dir = generated_root(root) / safe_id(str(split)) / safe_id(str(candidate.get("case_id"))) / safe_id(str(candidate.get("candidate_id")))
        manifest = write_project(out_dir, candidate_contract_source(candidate), {
            "poc_type": "selected_candidate_scaffold",
            "candidate_id": candidate.get("candidate_id"),
            "hypothesis_id": candidate.get("hypothesis_id"),
            "case_id": candidate.get("case_id"),
            "split": split,
            "pair_id": candidate.get("pair_id"),
            "version_kind": candidate.get("version_kind"),
            "source_case_path": candidate.get("source_case_path"),
            "fresh_independent_holdout": bool(candidate.get("fresh_independent_holdout")),
            "output_dir": str(out_dir.relative_to(root)),
        }, post_hoc_regression_only=(split == "patched-controls"))
        generated.append(manifest)
    result = {"status": "PASS", "split": split, "mode": "selected-candidates", "generated_count": len(generated), "generated": generated, "production_readiness_changed": False, "report_ready_created": False}
    summary_dir = precision_dir(root) if split == "patched-controls" else root / "scoring"
    summary_dir.mkdir(parents=True, exist_ok=True)
    summary_dir.joinpath("generated_poc_summary.json" if split == "patched-controls" else f"{split.replace('-', '_')}_generated_poc_summary.json").write_text(json.dumps(result, indent=2) + "\n")
    generated_root(root).joinpath("generated_poc_summary.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def generate_patch_regression(root: Path = PUBLIC_ROOT, *, split: str = "patched-controls") -> dict[str, Any]:
    plan = load_json(precision_dir(root) / "regenerated_patch_regression_test_plan.json", {}) or load_json(root / "scoring" / "patch_regression_test_plan.json", {})
    pairs = plan.get("pairs", [])
    if not pairs:
        result = {"status": "BLOCKED", "split": split, "mode": "patch-regression", "reason": "no patch-regression plan", "generated_count": 0, "generated": [], "production_readiness_changed": False}
        precision_dir(root).joinpath("patch_regression_poc_generation_summary.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    generated = []
    for row in pairs:
        if row.get("status") != "PASS":
            continue
        out_dir = generated_root(root) / safe_id(f"{row.get('pair_id')}_patch_regression")
        manifest = write_project(out_dir, patch_regression_contract_source(row), {
            "poc_type": "patch_regression_scaffold",
            "pair_id": row.get("pair_id"),
            "output_dir": str(out_dir.relative_to(root)),
        })
        generated.append(manifest)
    result = {"status": "PASS" if generated else "BLOCKED", "split": split, "mode": "patch-regression", "generated_count": len(generated), "generated": generated, "production_readiness_changed": False, "report_ready_created": False}
    precision_dir(root).joinpath("patch_regression_poc_generation_summary.json").write_text(json.dumps(result, indent=2) + "\n")
    generated_root(root).joinpath("patch_regression_poc_generation_summary.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Generate isolated local Foundry PoC scaffolds")
    p.add_argument("--root", default=str(PUBLIC_ROOT))
    p.add_argument("--split", default="patched-controls")
    p.add_argument("--selected-candidates", action="store_true")
    p.add_argument("--patch-regression", action="store_true")
    p.add_argument("--candidate", default="")
    p.add_argument("--repaired-candidate", default="")
    p.add_argument("--scaffold-only", action="store_true")
    p.add_argument("--fill-manual-required", action="store_true")
    p.add_argument("--batch-selected", action="store_true")
    p.add_argument("--expected-aligned-repaired-candidate", action="store_true")
    p.add_argument("--expected-aligned-candidate", default="")
    args = p.parse_args(argv)
    if args.expected_aligned_candidate and args.fill_manual_required:
        result = fill_expected_aligned_candidate_vertical_slice(Path(args.root), split=args.split, candidate_id=args.expected_aligned_candidate)
    elif args.expected_aligned_repaired_candidate:
        result = generate_expected_aligned_scaffold(Path(args.root), split=args.split, scaffold_only=args.scaffold_only)
    elif args.repaired_candidate and args.fill_manual_required:
        result = fill_repaired_candidate_vertical_slice(Path(args.root), split=args.split, candidate_id=args.repaired_candidate)
    elif args.repaired_candidate:
        result = generate_repaired_candidate_scaffold(Path(args.root), split=args.split, candidate_id=args.repaired_candidate, scaffold_only=args.scaffold_only)
    elif args.batch_selected and args.fill_manual_required:
        result = fill_batch_vertical_slices(Path(args.root))
    elif args.candidate and args.fill_manual_required:
        result = fill_manual_vertical_slice(Path(args.root), candidate_id=args.candidate)
    elif args.patch_regression:
        result = generate_patch_regression(Path(args.root), split=args.split)
    elif args.selected_candidates:
        result = generate_from_selected_candidates(Path(args.root), split=args.split)
    else:
        raise SystemExit("provide --selected-candidates or --patch-regression")
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") in {"PASS", "BLOCKED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
