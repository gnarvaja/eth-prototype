# eth-prototype


Prototype Ethereum Smart Contracts in Python


## Description

Library with base classes to prototype Ethereum Smart Contracts in Python. This includes:

- wadray: classes for fixed number of decimals math implemented with integers.
- contracts: classes to simulate contracts in Python with features like *rollback* on exception, external
  methods, views. Also classes for common contracts like ERC20 (tokens), ERC721 (NFTs) and AccessControl.
- w3wrappers: classes to wrap ethereum contracts called thru [web3py](https://web3py.readthedocs.io/) but with a pythonic interface

To use the `defender_relay` module you need to have the `warrant` package from this repo: https://github.com/gnarvaja/warrant. Add it to your requirements.txt as:

```
warrant @ git+https://github.com/gnarvaja/warrant.git#egg=warrant
```

Note that using the `warrant` package from pypi will not work because of incompatibilities with newer python versions.

## Tox Tests

The tox tests run in two variants:

- `default`: only uses and tests the prototype libraries, no blockchain.
- `default-w3`: users and tests two variants: prototype and w3wrappers (wrappers using web3py).

# Note

This project has been set up using PyScaffold 4.0.2. For details and usage
information on PyScaffold see https://pyscaffold.org/.
