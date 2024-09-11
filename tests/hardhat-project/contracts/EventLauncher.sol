// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

contract EventLauncher {
    event Event1(uint256 value);

    event Event2(uint256 value);

    function launchEvent1(uint256 value) public {
        emit Event1(value);
    }

    function launchEvent2(uint256 value) public {
        emit Event2(value);
    }
}
