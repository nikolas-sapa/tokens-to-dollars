// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./ERC20.sol";
import "./Vault.sol";
import "./NavOracle.sol";
import "./Compliance.sol";

/// @notice Two-step redemption facility for large exits. Shares are escrowed on
/// request and settled at the oracle NAV against the queue's asset buffer.
/// Settlement is permissionless so no redeemer can be griefed by an operator.
contract RedemptionQueue {
    struct Request {
        address user;
        uint256 shares;
        bool open;
    }

    Vault public immutable vault;
    ERC20 public immutable asset;
    NavOracle public immutable oracle;
    Compliance public immutable compliance;

    Request[] public requests;

    event Requested(uint256 indexed id, address indexed user, uint256 shares);
    event Settled(uint256 indexed id, uint256 assetsOut);
    event Cancelled(uint256 indexed id);

    constructor(Vault vault_, NavOracle oracle_, Compliance compliance_) {
        vault = vault_;
        asset = vault_.asset();
        oracle = oracle_;
        compliance = compliance_;
    }

    function requestRedemption(uint256 shares) external returns (uint256 id) {
        vault.transferFrom(msg.sender, address(this), shares);
        id = requests.length;
        requests.push(Request(msg.sender, shares, true));
        emit Requested(id, msg.sender, shares);
    }

    /// Settles an open request at the oracle NAV. Anyone may call this, in the
    /// same transaction as the request if they like — redemption is a right.
    function settle(uint256 id) external {
        Request storage r = requests[id];
        require(r.open, "closed");
        require(!compliance.isFrozen(r.user), "user frozen");
        (uint256 nav, ) = oracle.latestNav(); // drill:B4
        uint256 assetsOut = r.shares * nav / 1e18;
        r.open = false;
        vault.burnSettled(address(this), r.shares);
        asset.transfer(r.user, assetsOut);
        emit Settled(id, assetsOut);
    }

    /// Lets a redeemer take their escrowed shares back instead of settling.
    function cancel(uint256 id) external {
        Request storage r = requests[id];
        require(r.open, "closed");
        require(msg.sender == r.user, "not yours");
        require(!compliance.isFrozen(r.user), "user frozen"); // drill:B6
        r.open = false;
        vault.transfer(r.user, r.shares);
        emit Cancelled(id);
    }
}
