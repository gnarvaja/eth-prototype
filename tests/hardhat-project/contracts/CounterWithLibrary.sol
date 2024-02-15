// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import {Count} from "./Count.sol";

// Uncomment this line to use console.log
// import "hardhat/console.sol";

contract CounterWithLibrary {
    using Count for Count.Counter;

    Count.Counter public counter;

    constructor(uint initialValue)  {
        counter.initialize(initialValue);
    }

    function increase() public {
        counter.increase();
    }

    function value() public view returns (uint256) {
        return counter.value;
    }
}
