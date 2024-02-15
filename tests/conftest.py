"""
    Dummy conftest.py for ethproto.

    If you don't know what this is for, just leave it empty.
    Read more about conftest.py under:
    - https://docs.pytest.org/en/stable/fixture.html
    - https://docs.pytest.org/en/stable/writing_plugins.html
"""

import os

import pytest

from ethproto import w3wrappers, wrappers


def pytest_configure(config):
    wrappers.DEFAULT_PROVIDER = "w3"
    w3wrappers.CONTRACT_JSON_PATH = ["tests/hardhat-project"]
    os.environ["WEB3_PROVIDER_URI"] = "http://localhost:5350"


@pytest.fixture(scope="module", autouse=True)
def reset_provider():
    """Resets the provider for each module. Mainly for addressbook and contract map cleanse"""
    from web3 import Web3

    from ethproto.w3wrappers import W3Provider

    wrappers.register_provider("w3", W3Provider(Web3()))
    yield
    wrappers.register_provider("w3", W3Provider(Web3()))


# @pytest.fixture(autouse=True, scope="session")
# def hardhat_compile():
