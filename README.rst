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
- wrappers: classes to wrap ethereum contracts called thru brownie but with a pythonic interface


.. _pyscaffold-notes:

Note
====

This project has been set up using PyScaffold 4.0.2. For details and usage
information on PyScaffold see https://pyscaffold.org/.
