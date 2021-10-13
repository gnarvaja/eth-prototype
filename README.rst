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


Tox Tests
=========

To run the tox tests, you need an environment with Brownie, SOLC and other requirements.

You can do it using a Docker image an a few commands

.. code-block:: bash

   docker run -it -v $PWD:/code gnarvaja/eth-dev:1.0.0 bash
   cd /code
   pip install tox
   brownie pm install OpenZeppelin/openzeppelin-contracts@4.3.2
   tox


.. _pyscaffold-notes:

Note
====

This project has been set up using PyScaffold 4.0.2. For details and usage
information on PyScaffold see https://pyscaffold.org/.
