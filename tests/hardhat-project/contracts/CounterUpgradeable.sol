// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

// Uncomment this line to use console.log
// import "hardhat/console.sol";

contract CounterUpgradeable is UUPSUpgradeable {
    uint public value;
    address public owner;


    constructor()  {
        _disableInitializers();
    }

    function initialize(uint initialValue)  initializer public {
        owner = msg.sender;
        value = initialValue;
    }

    function _authorizeUpgrade(address newImplementation) internal view override {
        require(msg.sender == owner, "Unauthorized");
        require(newImplementation != address(0), "New implementation is required");
    }


    function increase() public {
        value += 1;
    }
}
