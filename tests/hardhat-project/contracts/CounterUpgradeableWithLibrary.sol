// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import {Count} from "./Count.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

// Uncomment this line to use console.log
// import "hardhat/console.sol";

contract CounterUpgradeableWithLibrary is UUPSUpgradeable{
    using Count for Count.Counter;

    Count.Counter public counter;
    address public owner;

    constructor()  {
        _disableInitializers();
    }
    function initialize(uint initialValue)  initializer public   {
        counter.initialize(initialValue);
    }

    function _authorizeUpgrade(address newImplementation) internal view override {
        require(msg.sender == owner, "Unauthorized");
        require(newImplementation != address(0), "New implementation is required");
    }

    function increase() public {
        counter.increase();
    }

    function value() public view returns (uint256) {
        return counter.value;
    }
}
