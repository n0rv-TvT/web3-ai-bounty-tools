// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../common/MockERC20.sol";

contract VulnerableRewards {
    MockERC20 public immutable stakingToken;
    MockERC20 public immutable rewardToken;
    uint256 public totalStaked;
    uint256 public accRewardPerShare;
    uint256 public accountedRewards;
    mapping(address => uint256) public stakeOf;
    mapping(address => uint256) public rewardDebt;

    constructor(MockERC20 _stakingToken, MockERC20 _rewardToken) {
        stakingToken = _stakingToken;
        rewardToken = _rewardToken;
    }

    function fund(uint256 amount) external {
        // BUG: rewards are transferred without settling accumulator first.
        rewardToken.transferFrom(msg.sender, address(this), amount);
    }

    function updateRewards() public {
        uint256 balance = rewardToken.balanceOf(address(this));
        uint256 pending = balance - accountedRewards;
        if (totalStaked > 0 && pending > 0) {
            accRewardPerShare += pending * 1e18 / totalStaked;
            accountedRewards = balance;
        }
    }

    function stake(uint256 amount) external {
        stakingToken.transferFrom(msg.sender, address(this), amount);
        stakeOf[msg.sender] += amount;
        totalStaked += amount;
        rewardDebt[msg.sender] = stakeOf[msg.sender] * accRewardPerShare / 1e18;
    }

    function claim() external {
        updateRewards();
        uint256 accumulated = stakeOf[msg.sender] * accRewardPerShare / 1e18;
        uint256 claimable = accumulated - rewardDebt[msg.sender];
        rewardDebt[msg.sender] = accumulated;
        accountedRewards -= claimable;
        rewardToken.transfer(msg.sender, claimable);
    }
}
