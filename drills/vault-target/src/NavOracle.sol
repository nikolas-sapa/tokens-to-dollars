// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice NAV feed for the vault's underlying portfolio. The portfolio is
/// off-chain RWA collateral, so the net asset value is computed off-chain and
/// published on a daily cadence by the operations desk.
contract NavOracle {
    uint256 public constant HEARTBEAT = 24 hours;

    uint256 public nav;
    uint256 public updatedAt;
    address public updater;

    event NavUpdated(uint256 nav, uint256 at);

    constructor(address updater_) { updater = updater_; }

    function updateNav(uint256 nav_) external {
        require(msg.sender == updater, "not updater");
        nav = nav_;
        updatedAt = block.timestamp;
        emit NavUpdated(nav_, block.timestamp);
    }

    function latestNav() external view returns (uint256, uint256) {
        return (nav, updatedAt);
    }
}
