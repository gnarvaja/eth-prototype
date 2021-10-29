=============
eth-prototype
=============


Prototype Ethereum Smart Contracts in Python


Description
===========

Library with base classes to prototype Ethereum Smart Contracts in Python. This includes:

- wadray: classes for fixed number of decimals math implemented with integers.
- contracts: classes to simulate contracts in Python with features like *rollback* on exception, external
  methods, views. Also classes for common contracts like ERC20 (tokens), ERC721 (NFTs) and AccessControl.
- brwrappers: classes to wrap ethereum contracts called thru [brownie](https://github.com/eth-brownie/brownie/) but with a pythonic interface
- w3wrappers: classes to wrap ethereum contracts called thru [web3py](https://web3py.readthedocs.io/) but with a pythonic interface


Tox Tests
=========

The tox tests run in three variants:

- `default`: only uses and tests the prototype libraries, no blockchain.
- `default-w3`: users and tests two variants: prototype and w3wrappers (wrappers using web3py).
- `default-br`: users and tests two variants: prototype and brwrappers (wrappers using brownie).

It's not possible for now running all the tests together because of incompatibilities between brownie and web3[tester].


To run the tox `default-br` tests, you need an environment with Brownie, SOLC and other requirements.

You can do it using a Docker image an a few commands

.. code-block:: bash

   docker run -it -v $PWD:/code -w /code gnarvaja/eth-dev:1.0.0 bash
   gnarvaja/eth-dev:eth-proto-brownie
   pip install tox
   brownie pm install OpenZeppelin/openzeppelin-contracts@4.3.2
   brownie pm install OpenZeppelin/openzeppelin-contracts-upgradeable@4.3.2
   tox -e py39-br

   docker run -it -v $PWD:/code -w /code gnarvaja/eth-dev:eth-proto-brownie bash
   tox -e py39-br

.. _pyscaffold-notes:

Note
====

This project has been set up using PyScaffold 4.0.2. For details and usage
information on PyScaffold see https://pyscaffold.org/.
