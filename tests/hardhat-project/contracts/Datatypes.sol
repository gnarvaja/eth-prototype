// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.9;


import "hardhat/console.sol";

/**
 * @title Datatypes
 * @notice Simple contract to test python wrappers datatype handling
 */
contract Datatypes {
    constructor() {}

    function echoAddress(address a) external pure returns (address) {
        console.log(a);
        return address(a);
    }
}
