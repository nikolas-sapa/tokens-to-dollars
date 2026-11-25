// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Actors for the local fork-test harness. Never used on mainnet.
library TestKeys {
    address internal constant ALICE = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
    uint256 internal constant ALICE_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80; // gitleaks:allow // drill:T4
    address internal constant BOB = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    uint256 internal constant BOB_KEY = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d; // gitleaks:allow
}
