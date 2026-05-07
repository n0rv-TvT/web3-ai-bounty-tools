// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../common/MockERC20.sol";

contract PublicMutableOracle {
    uint256 public price = 1e18;

    function setPrice(uint256 newPrice) external {
        // BUG for this fixture: anyone can set the price used by lending.
        price = newPrice;
    }
}

contract VulnerableLending {
    MockERC20 public immutable collateral;
    MockERC20 public immutable debt;
    PublicMutableOracle public immutable oracle;
    mapping(address => uint256) public collateralOf;
    mapping(address => uint256) public debtOf;

    constructor(MockERC20 _collateral, MockERC20 _debt, PublicMutableOracle _oracle) {
        collateral = _collateral;
        debt = _debt;
        oracle = _oracle;
    }

    function deposit(uint256 amount) external {
        collateral.transferFrom(msg.sender, address(this), amount);
        collateralOf[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        uint256 collateralValue = collateralOf[msg.sender] * oracle.price() / 1e18;
        require(debtOf[msg.sender] + amount <= collateralValue / 2, "ltv");
        debtOf[msg.sender] += amount;
        debt.transfer(msg.sender, amount);
    }

    function badDebt(address user) external view returns (uint256) {
        uint256 safeDebt = collateralOf[user] * oracle.price() / 1e18 / 2;
        return debtOf[user] > safeDebt ? debtOf[user] - safeDebt : 0;
    }
}
