#!/usr/bin/env python3
"""Schema-backed economic proof engine for Web3 bounty triage.

The schema is the contract. This module fails closed if
schemas/economic_proof.schema.json is missing or if an emitted proof does not
validate against it. Nothing that touches lead status is allowed to invent a
parallel output format.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, getcontext
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "1.0.0"
ENGINE_VERSION = "0.1.0"
BPS_DENOMINATOR = Decimal("10000")

getcontext().prec = 60


def economic_proof_schema_path() -> Path:
    """Return required schemas/economic_proof.schema.json path."""

    return Path(__file__).resolve().parents[1] / "schemas" / "economic_proof.schema.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> dict[str, Any]:
    """Load JSON input, lead DB, or schema."""

    if not path.exists():
        raise SystemExit(f"JSON file does not exist: {path}")
    data = json.loads(path.read_text(errors="replace"))
    if not isinstance(data, dict):
        raise SystemExit(f"JSON root must be an object: {path}")
    return data


def _decimal(value: Any, field: str) -> Decimal:
    try:
        d = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise SystemExit(f"Invalid decimal for {field}: {value}") from exc
    if not d.is_finite():
        raise SystemExit(f"Invalid finite decimal for {field}: {value}")
    return d


def _require_positive(value: Decimal, field: str) -> None:
    if value <= 0:
        raise SystemExit(f"{field} must be > 0, got {value}")


def _fmt(value: Decimal) -> str:
    if value == 0:
        return "0"
    normalized = value.normalize()
    text = format(normalized, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def validate_economic_proof(proof: dict[str, Any], schema_path: Path | None = None) -> None:
    """Raise SystemExit if proof does not validate against economic_proof.schema.json."""

    schema_file = schema_path or economic_proof_schema_path()
    if not schema_file.exists():
        raise SystemExit(f"Missing required economic proof schema: {schema_file}")
    try:
        import jsonschema  # type: ignore
    except ImportError as exc:
        raise SystemExit("jsonschema is required to validate economic proofs") from exc

    schema = load_json(schema_file)
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(proof), key=lambda e: list(e.path))
    if errors:
        lines = []
        for error in errors:
            loc = "/" + "/".join(str(x) for x in error.path)
            lines.append(f"{loc}: {error.message}")
        raise SystemExit("Economic proof validation failed:\n- " + "\n- ".join(lines))


def constant_product_quote_in_for_price_multiplier(
    *,
    reserve_base: Decimal,
    reserve_quote: Decimal,
    target_price_multiplier: Decimal,
    pool_fee_bps: Decimal,
) -> dict[str, Decimal]:
    """
    Compute quote input, base output, and mark-to-market manipulation loss
    for moving a constant-product spot price by target_price_multiplier.
    """

    _require_positive(reserve_base, "reserve_base")
    _require_positive(reserve_quote, "reserve_quote")
    _require_positive(target_price_multiplier, "target_price_multiplier")
    if pool_fee_bps < 0 or pool_fee_bps >= BPS_DENOMINATOR:
        raise SystemExit(f"pool_fee_bps must be >= 0 and < 10000, got {pool_fee_bps}")

    sqrt_multiplier = target_price_multiplier.sqrt()
    new_base = reserve_base / sqrt_multiplier
    new_quote = reserve_quote * sqrt_multiplier
    net_quote_added = new_quote - reserve_quote
    base_output = reserve_base - new_base
    if net_quote_added < 0 or base_output < 0:
        raise SystemExit("Only quote-in price-increase manipulation is supported in this model")

    fee_multiplier = Decimal("1") - (pool_fee_bps / BPS_DENOMINATOR)
    gross_quote_input = net_quote_added / fee_multiplier if fee_multiplier else Decimal("Infinity")
    initial_price_quote_per_base = reserve_quote / reserve_base
    mark_to_market_loss_quote = gross_quote_input - (base_output * initial_price_quote_per_base)

    return {
        "reserve_base_before": reserve_base,
        "reserve_quote_before": reserve_quote,
        "reserve_base_after": new_base,
        "reserve_quote_after": new_quote,
        "target_price_multiplier": target_price_multiplier,
        "pool_fee_bps": pool_fee_bps,
        "gross_quote_input": gross_quote_input,
        "net_quote_added": net_quote_added,
        "base_output": base_output,
        "mark_to_market_loss_quote": mark_to_market_loss_quote,
    }


def run_break_even_sensitivity(base_proof: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    """Compute break-even under gas, fee, slippage, and liquidity shocks from the base proof."""

    del request  # Sensitivity intentionally wraps the emitted proof values.
    gross = _decimal(base_proof["profitability"]["gross_revenue_usd"], "profitability.gross_revenue_usd")
    gas = _decimal(base_proof["costs"]["gas_cost_usd"], "costs.gas_cost_usd")
    flash = _decimal(base_proof["costs"]["flash_loan_fee_usd"], "costs.flash_loan_fee_usd")
    manipulation = _decimal(base_proof["costs"]["manipulation_cost_usd"], "costs.manipulation_cost_usd")
    total_without_gas = flash + manipulation
    total_cost = total_without_gas + gas

    return {
        "break_even_gas_cost_usd": _fmt(gross - total_without_gas),
        "break_even_total_cost_usd": _fmt(gross),
        "minimum_bad_debt_for_profit_usd": _fmt(total_cost),
        "net_profit_if_gas_doubles_usd": _fmt(gross - total_cost - gas),
        "net_profit_if_flash_fee_doubles_usd": _fmt(gross - total_cost - flash),
        "net_profit_if_manipulation_cost_doubles_usd": _fmt(gross - total_cost - manipulation),
    }


def recommend_lead_exit(proof: dict[str, Any]) -> dict[str, Any]:
    """
    Return schema-backed lead exit:
    REPORT_READY only if net profit > 0 and concrete protocol loss/bad debt > 0.
    Otherwise KILL.
    """

    net_profit = _decimal(proof["profitability"]["net_profit_usd"], "profitability.net_profit_usd")
    bad_debt = _decimal(proof["impact"]["bad_debt_usd"], "impact.bad_debt_usd")
    protocol_loss = _decimal(proof["impact"]["protocol_loss_usd"], "impact.protocol_loss_usd")
    if net_profit > 0 and bad_debt > 0 and protocol_loss > 0:
        return {"status": "REPORT_READY", "reason": "positive net profit and concrete bad debt proven"}
    return {"status": "KILL", "reason": "not profitable after flash loan fee, manipulation cost, and gas"}


def model_flash_loan_oracle_attack(
    request: dict[str, Any],
    *,
    schema_path: Path | None = None,
) -> dict[str, Any]:
    """
    Main engine.
    Input: economic modeling request.
    Output: economic_proof.schema.json-conforming proof.
    Verdict must be REPORT_READY or KILL.
    """

    schema_file = schema_path or economic_proof_schema_path()
    if not schema_file.exists():
        raise SystemExit(f"Missing required economic proof schema: {schema_file}")

    market = request.get("market") or {}
    position = request.get("position") or {}
    costs = request.get("costs") or {}
    if not isinstance(market, dict) or not isinstance(position, dict) or not isinstance(costs, dict):
        raise SystemExit("request.market, request.position, and request.costs must be objects")

    reserve_base = _decimal(market.get("reserve_base"), "market.reserve_base")
    reserve_quote = _decimal(market.get("reserve_quote"), "market.reserve_quote")
    pool_fee_bps = _decimal(market.get("pool_fee_bps"), "market.pool_fee_bps")
    true_price_usd = _decimal(market.get("true_price_usd"), "market.true_price_usd")
    target_price_multiplier = _decimal(market.get("target_price_multiplier"), "market.target_price_multiplier")
    quote_token_price_usd = _decimal(
        market.get("quote_token_price_usd", position.get("debt_token_price_usd", "1")),
        "market.quote_token_price_usd",
    )
    collateral_amount = _decimal(position.get("collateral_amount"), "position.collateral_amount")
    max_ltv_bps = _decimal(position.get("max_ltv_bps"), "position.max_ltv_bps")
    debt_token_price_usd = _decimal(position.get("debt_token_price_usd"), "position.debt_token_price_usd")
    flash_loan_fee_bps = _decimal(costs.get("flash_loan_fee_bps"), "costs.flash_loan_fee_bps")
    gas_cost_usd = _decimal(costs.get("gas_cost_usd"), "costs.gas_cost_usd")

    _require_positive(true_price_usd, "market.true_price_usd")
    _require_positive(quote_token_price_usd, "market.quote_token_price_usd")
    _require_positive(collateral_amount, "position.collateral_amount")
    _require_positive(debt_token_price_usd, "position.debt_token_price_usd")
    if max_ltv_bps <= 0 or max_ltv_bps > BPS_DENOMINATOR:
        raise SystemExit(f"position.max_ltv_bps must be > 0 and <= 10000, got {max_ltv_bps}")
    if flash_loan_fee_bps < 0:
        raise SystemExit(f"costs.flash_loan_fee_bps must be >= 0, got {flash_loan_fee_bps}")
    if gas_cost_usd < 0:
        raise SystemExit(f"costs.gas_cost_usd must be >= 0, got {gas_cost_usd}")

    amm = constant_product_quote_in_for_price_multiplier(
        reserve_base=reserve_base,
        reserve_quote=reserve_quote,
        target_price_multiplier=target_price_multiplier,
        pool_fee_bps=pool_fee_bps,
    )

    ltv = max_ltv_bps / BPS_DENOMINATOR
    manipulated_price_usd = true_price_usd * target_price_multiplier
    max_borrow_usd = collateral_amount * manipulated_price_usd * ltv
    true_safe_debt_usd = collateral_amount * true_price_usd * ltv
    bad_debt_usd = max_borrow_usd - true_safe_debt_usd
    raw_collateral_shortfall_usd = max_borrow_usd - (collateral_amount * true_price_usd)
    if bad_debt_usd < 0:
        bad_debt_usd = Decimal("0")
    if raw_collateral_shortfall_usd < 0:
        raw_collateral_shortfall_usd = Decimal("0")

    manipulation_cost_usd = amm["mark_to_market_loss_quote"] * quote_token_price_usd
    flash_loan_fee_usd = amm["gross_quote_input"] * quote_token_price_usd * flash_loan_fee_bps / BPS_DENOMINATOR
    total_cost_usd = manipulation_cost_usd + flash_loan_fee_usd + gas_cost_usd
    gross_revenue_usd = bad_debt_usd
    net_profit_usd = gross_revenue_usd - total_cost_usd

    proof: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "engine": {"name": "economic_modeler.py", "version": ENGINE_VERSION},
        "lead_id": str(request.get("lead_id") or "unknown"),
        "bug_class": str(request.get("bug_class") or "oracle-price-manipulation-or-staleness"),
        "attack_type": str(request.get("attack_type") or "flash-loan-oracle-bad-debt"),
        "verdict": "KILL",
        "inputs": {
            "market": {
                "reserve_base": _fmt(reserve_base),
                "reserve_quote": _fmt(reserve_quote),
                "pool_fee_bps": _fmt(pool_fee_bps),
                "true_price_usd": _fmt(true_price_usd),
                "quote_token_price_usd": _fmt(quote_token_price_usd),
                "target_price_multiplier": _fmt(target_price_multiplier),
            },
            "position": {
                "collateral_amount": _fmt(collateral_amount),
                "max_ltv_bps": _fmt(max_ltv_bps),
                "debt_token_price_usd": _fmt(debt_token_price_usd),
            },
            "costs": {
                "flash_loan_fee_bps": _fmt(flash_loan_fee_bps),
                "gas_cost_usd": _fmt(gas_cost_usd),
            },
        },
        "amm_manipulation": {
            "reserve_base_before": _fmt(amm["reserve_base_before"]),
            "reserve_quote_before": _fmt(amm["reserve_quote_before"]),
            "reserve_base_after": _fmt(amm["reserve_base_after"]),
            "reserve_quote_after": _fmt(amm["reserve_quote_after"]),
            "target_price_multiplier": _fmt(target_price_multiplier),
            "pool_fee_bps": _fmt(pool_fee_bps),
            "gross_quote_input": _fmt(amm["gross_quote_input"]),
            "net_quote_added": _fmt(amm["net_quote_added"]),
            "base_output": _fmt(amm["base_output"]),
            "manipulation_cost_usd": _fmt(manipulation_cost_usd),
        },
        "impact": {
            "manipulated_price_usd": _fmt(manipulated_price_usd),
            "true_price_usd": _fmt(true_price_usd),
            "max_borrow_usd": _fmt(max_borrow_usd),
            "true_safe_debt_usd": _fmt(true_safe_debt_usd),
            "bad_debt_usd": _fmt(bad_debt_usd),
            "protocol_loss_usd": _fmt(bad_debt_usd),
            "raw_collateral_shortfall_usd": _fmt(raw_collateral_shortfall_usd),
        },
        "costs": {
            "flash_loan_fee_usd": _fmt(flash_loan_fee_usd),
            "gas_cost_usd": _fmt(gas_cost_usd),
            "manipulation_cost_usd": _fmt(manipulation_cost_usd),
            "total_cost_usd": _fmt(total_cost_usd),
        },
        "profitability": {
            "gross_revenue_usd": _fmt(gross_revenue_usd),
            "total_cost_usd": _fmt(total_cost_usd),
            "net_profit_usd": _fmt(net_profit_usd),
            "break_even": net_profit_usd <= 0,
        },
        "sensitivity": {},
        "lead_exit": {"status": "KILL", "reason": "not profitable after flash loan fee, manipulation cost, and gas"},
        "validation": {
            "schema_validated": False,
            "positive_net_profit": net_profit_usd > 0,
            "concrete_bad_debt": bad_debt_usd > 0,
            "economic_proof_required_for_report_ready": True,
        },
    }
    proof["sensitivity"] = run_break_even_sensitivity(proof, request)
    lead_exit = recommend_lead_exit(proof)
    proof["lead_exit"] = lead_exit
    proof["verdict"] = lead_exit["status"]

    validation_probe = dict(proof)
    validation_probe["validation"] = dict(proof["validation"])
    validation_probe["validation"]["schema_validated"] = True
    validate_economic_proof(validation_probe, schema_file)
    proof = validation_probe
    return proof


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build schema-backed economic proofs for Web3 leads")
    parser.add_argument("request", help="economic modeling request JSON")
    parser.add_argument("--schema", help="override economic_proof.schema.json path")
    parser.add_argument("--json", dest="json_path", help="write economic proof JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    proof = model_flash_loan_oracle_attack(load_json(Path(args.request)), schema_path=Path(args.schema) if args.schema else None)
    if args.json_path:
        out = Path(args.json_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(proof, indent=2) + "\n")
    else:
        print(json.dumps(proof, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
