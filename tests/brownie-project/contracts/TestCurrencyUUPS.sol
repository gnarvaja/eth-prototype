//SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
// Don't remove it - required to find the ERC1967Proxy in brownie
import {ERC1967Proxy as OZERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract TestCurrencyUUPS is ERC20Upgradeable {
  address private _owner;

  function initialize(
    string memory name_,
    string memory symbol_,
    uint256 initialSupply
  ) public initializer {
    _owner = _msgSender();
    __ERC20_init(name_, symbol_);
    _mint(_owner, initialSupply);
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

contract ERC1967Proxy is OZERC1967Proxy {
  constructor(address _logic, bytes memory _data) OZERC1967Proxy(_logic, _data) payable {}
}
