// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../common/MockERC20.sol";

contract VulnerableVault {
    MockERC20 public immutable asset;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(MockERC20 _asset) {
        asset = _asset;
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        uint256 supply = totalSupply;
        uint256 assetsBefore = totalAssets();
        shares = supply == 0 ? assets : assets * supply / assetsBefore;
        // BUG: no minimum shares check and no virtual shares/assets.
        asset.transferFrom(msg.sender, address(this), assets);
        balanceOf[receiver] += shares;
        totalSupply += shares;
    }

    function redeem(uint256 shares, address receiver) external returns (uint256 assets) {
        assets = shares * totalAssets() / totalSupply;
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        asset.transfer(receiver, assets);
    }
}
