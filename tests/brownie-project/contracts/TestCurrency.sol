//SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract TestCurrency is ERC20 {
  address private _owner;

  constructor(
    string memory name_,
    string memory symbol_,
    uint256 initialSupply
  ) ERC20(name_, symbol_) {
    _owner = msg.sender;
    _mint(msg.sender, initialSupply);
  }

  function mint(address recipient, uint256 amount) external {
    // require(msg.sender == _owner, "Only owner can mint");
    return _mint(recipient, amount);
  }

  function burn(address recipient, uint256 amount) external {
    // require(msg.sender == _owner, "Only owner can burn");
    return _burn(recipient, amount);
  }
}
