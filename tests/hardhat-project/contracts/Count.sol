// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.9;


library Count {
    struct Counter {
        uint256 value;
    }

    function initialize(Counter storage counter, uint256 value) external {
        counter.value = value;
    }

    function increase(Counter storage counter) external {
        counter.value += 1;
    }

}
