// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal storage-version tracker, OpenZeppelin-shaped but trimmed.
/// `initializer` consumes version 1; `reinitializer(v)` may only run while the
/// recorded version is strictly below v.
abstract contract Initializable {
    uint64 private _initialized;

    event Initialized(uint64 version);

    modifier initializer() {
        require(_initialized == 0, "already initialized");
        _initialized = 1;
        _;
        emit Initialized(1);
    }

    modifier reinitializer(uint64 version) {
        require(_initialized < version, "version already applied");
        _initialized = version;
        _;
        emit Initialized(version);
    }

    function initializedVersion() public view returns (uint64) {
        return _initialized;
    }
}
