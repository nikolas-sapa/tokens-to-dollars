// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal 48h timelock. Scheduled operations become executable after
/// the delay; execution is permissionless once ripe (standard pattern).
contract Timelock {
    uint256 public constant DELAY = 48 hours;

    address public admin;
    mapping(bytes32 => uint256) public executableAt;

    event Scheduled(bytes32 indexed id, address target, uint256 executableAt);
    event Executed(bytes32 indexed id);

    constructor() { admin = msg.sender; }

    function schedule(address target, bytes calldata data) external returns (bytes32 id) {
        require(msg.sender == admin, "not admin");
        id = keccak256(abi.encode(target, data));
        executableAt[id] = block.timestamp + DELAY;
        emit Scheduled(id, target, executableAt[id]);
    }

    function execute(address target, bytes calldata data) external {
        bytes32 id = keccak256(abi.encode(target, data));
        uint256 at = executableAt[id];
        require(at != 0 && block.timestamp >= at, "not ready");
        executableAt[id] = 0;
        (bool ok, bytes memory ret) = target.call(data);
        require(ok, string(ret));
        emit Executed(id);
    }
}
