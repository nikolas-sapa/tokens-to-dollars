// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Compliance freeze registry — RWA transfer-restriction layer.
/// Freezing blocks token movement for the account at the token level.
contract Compliance {
    address public owner;
    mapping(address => bool) public isFrozen;

    event Frozen(address indexed account, bool flag);

    constructor() { owner = msg.sender; }

    function setFrozen(address account, bool flag) external {
        require(msg.sender == owner, "not owner");
        isFrozen[account] = flag;
        emit Frozen(account, flag);
    }
}
