// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IBlacklist {
    function isBlacklisted(address account) external view returns (bool);
}
