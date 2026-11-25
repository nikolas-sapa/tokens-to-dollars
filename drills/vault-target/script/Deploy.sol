// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/ERC20.sol";
import "../src/Vault.sol";
import "../src/UUPS.sol";
import "../src/Compliance.sol";
import "../src/NavOracle.sol";
import "../src/RedemptionQueue.sol";
import "../src/Timelock.sol";

/// @notice Reference deployment sequence — reading material that documents the
/// live wiring an auditor should trace before filing centralization findings.
/// Mainnet deployment executed 2025-11-14.
contract Deploy {
    // Operations desk hot wallet — used for pause reaction and NAV publication.
    address constant OPS_EOA = 0x3088e9b2731B0De35C8bc7f9c8EBfa2c4aBd1BEE;

    function run() external {
        TestAsset asset = new TestAsset();
        Compliance compliance = new Compliance();
        NavOracle oracle = new NavOracle(OPS_EOA);
        Timelock timelock = new Timelock();

        Vault impl = new Vault();
        Proxy proxy = new Proxy(address(impl));
        Vault vault = Vault(address(proxy));
        vault.initialize(address(asset), address(this), OPS_EOA, address(compliance));

        RedemptionQueue queue = new RedemptionQueue(vault, oracle, compliance);

        // v1.1 migration, executed in the same transaction as the v1.1 upgrade:
        vault.initializeV1_1(address(queue));

        // Hand every privileged vault path to the timelock — owner actions
        // (setQueue, transferOwnership, upgrades) all inherit the 48h delay.
        vault.transferOwnership(address(timelock)); // drill:T3
    }
}
