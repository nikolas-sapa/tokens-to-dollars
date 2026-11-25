// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./ERC20.sol";

/// @notice Merkle-distributed airdrop of vault shares to early LPs.
/// Claimants present a proof of their (account, amount) leaf against the root.
contract MerkleAirdrop {
    ERC20 public immutable token;
    address public owner;
    bytes32 public merkleRoot;

    mapping(address => bool) public claimed;

    event Claimed(address indexed account, uint256 amount);
    event RootRotated(bytes32 root);

    constructor(ERC20 token_, bytes32 root_) {
        token = token_; merkleRoot = root_; owner = msg.sender;
    }

    /// Rotates the root when a new distribution round is published.
    function setMerkleRoot(bytes32 root_) external {
        require(msg.sender == owner, "not owner");
        merkleRoot = root_;
        emit RootRotated(root_);
    }

    function claim(uint256 amount, bytes32[] calldata proof) external {
        require(!claimed[msg.sender], "already claimed");
        bytes32 leaf = keccak256(abi.encode(msg.sender, amount));
        require(_verify(proof, leaf), "bad proof");
        token.transfer(msg.sender, amount); // drill:B3
        emit Claimed(msg.sender, amount);
    }

    function _verify(bytes32[] calldata proof, bytes32 leaf) internal view returns (bool) {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 sibling = proof[i];
            computed = computed < sibling
                ? keccak256(abi.encodePacked(computed, sibling))
                : keccak256(abi.encodePacked(sibling, computed));
        }
        return computed == merkleRoot;
    }
}
