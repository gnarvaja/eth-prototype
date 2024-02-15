// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

// Uncomment this line to use console.log
// import "hardhat/console.sol";

contract Counter {
    uint public value;

    constructor(uint initialValue)  {
        value = initialValue;
    }

    function increase() public {
        value += 1;
    }
}
