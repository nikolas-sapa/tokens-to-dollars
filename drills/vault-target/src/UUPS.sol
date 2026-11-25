// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal ERC-1967 UUPS upgrade logic. Executed via delegatecall in the
/// proxy's context, so the implementation slot write lands in proxy storage.
abstract contract UUPS {
    // keccak256("eip1967.proxy.implementation") - 1
    bytes32 internal constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    event Upgraded(address indexed implementation);

    function upgradeToAndCall(address newImplementation, bytes calldata data) external {
        _authorizeUpgrade(newImplementation);
        assembly {
            sstore(IMPL_SLOT, newImplementation)
        }
        emit Upgraded(newImplementation);
        if (data.length > 0) {
            (bool ok, bytes memory ret) = newImplementation.delegatecall(data);
            require(ok, string(ret));
        }
    }

    function _authorizeUpgrade(address newImplementation) internal virtual;
}

/// @notice Minimal ERC-1967 proxy — fixed implementation at construction, UUPS-owned upgrades.
contract Proxy {
    bytes32 internal constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address implementation) {
        assembly {
            sstore(IMPL_SLOT, implementation)
        }
    }

    fallback() external payable {
        assembly {
            let impl := sload(IMPL_SLOT)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
