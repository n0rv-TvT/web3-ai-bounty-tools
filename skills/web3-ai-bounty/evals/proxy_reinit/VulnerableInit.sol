// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableInit {
    address public owner;
    address public treasury;

    function initialize(address _owner, address _treasury) external {
        // BUG: missing initializer guard.
        owner = _owner;
        treasury = _treasury;
    }

    function sweep(address token, bytes calldata callData) external {
        require(msg.sender == owner, "not owner");
        (bool ok,) = token.call(callData);
        require(ok, "sweep failed");
    }
}
