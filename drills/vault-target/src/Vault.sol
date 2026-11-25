// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./ERC20.sol";
import "./Initializable.sol";
import "./UUPS.sol";
import "./Compliance.sol";

/// @notice RWA-style yield vault, ERC-4626-shaped and UUPS-upgradeable.
/// Deposits settle instantly against the vault's asset balance. Large
/// redemptions route through RedemptionQueue at the oracle NAV instead.
contract Vault is ERC20, Initializable, UUPS {
    ERC20 public asset;
    address public owner;
    address public pauser;
    bool public depositsPaused;
    Compliance public compliance;
    address public queue;

    event Paused(bool flag);
    event OwnershipTransferred(address indexed prev, address indexed next);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function initialize(address asset_, address owner_, address pauser_, address compliance_) external initializer {
        asset = ERC20(asset_);
        owner = owner_;
        pauser = pauser_;
        compliance = Compliance(compliance_);
        name = "Drill Vault Share";
        symbol = "vRWA";
    }

    /// v1.1 migration — executed 2025-11-14 per script/Deploy.sol.
    function initializeV1_1(address queue_) external reinitializer(2) {
        queue = queue_;
    }

    /// v2 migration — rewires queue and compliance after the v2 implementation upgrade.
    /// Must run exactly once, immediately post-upgrade.
    function initializeV2(address queue_, address compliance_) external reinitializer(2) { // drill:B5
        queue = queue_;
        compliance = Compliance(compliance_);
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply;
        return supply == 0 ? assets : assets * supply / totalAssets(); // drill:B1
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        uint256 supply = totalSupply;
        return supply == 0 ? shares : shares * totalAssets() / supply;
    }

    /// Shares owed for a withdrawal, rounded up — the withdrawer pays the
    /// rounding dust, the vault never does.
    function previewWithdraw(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply;
        if (supply == 0) return assets;
        return (assets * supply + totalAssets() - 1) / totalAssets(); // drill:T1
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        require(!depositsPaused, "deposits paused");
        shares = convertToShares(assets);
        require(shares > 0, "zero shares");
        asset.transferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares);
    }

    function withdraw(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = previewWithdraw(assets);
        _burn(msg.sender, shares);
        asset.transfer(receiver, assets);
    }

    /// Queue-only burn so settled redemption shares leave supply.
    function burnSettled(address from, uint256 shares) external {
        require(msg.sender == queue, "not queue");
        _burn(from, shares);
    }

    function setPaused(bool flag) external {
        require(msg.sender == pauser, "not pauser"); // drill:T2
        depositsPaused = flag;
        emit Paused(flag);
    }

    function setQueue(address queue_) external onlyOwner {
        queue = queue_;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function _authorizeUpgrade(address) internal override {} // drill:B2

    function _transfer(address from, address to, uint256 amount) internal override {
        require(!compliance.isFrozen(from) && !compliance.isFrozen(to), "frozen");
        super._transfer(from, to, amount);
    }
}
