// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../common/MockERC20.sol";

contract VulnerableWithdraw {
    MockERC20 public immutable token;
    address public immutable signer;

    constructor(MockERC20 _token, address _signer) {
        token = _token;
        signer = _signer;
    }

    function withdraw(address to, uint256 amount, bytes calldata signature) external {
        // BUG: signature omits nonce, deadline, chainId, and verifying contract.
        bytes32 digest = keccak256(abi.encodePacked(to, amount));
        require(_recover(digest, signature) == signer, "bad signature");
        token.transfer(to, amount);
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(digest, v, r, s);
    }
}
