"""
    Dummy conftest.py for ethproto.

    If you don't know what this is for, just leave it empty.
    Read more about conftest.py under:
    - https://docs.pytest.org/en/stable/fixture.html
    - https://docs.pytest.org/en/stable/writing_plugins.html
"""

import os

import pytest


def pytest_configure(config):
    if os.environ.get("TEST_ENV", None) != "web3py":
        return

    from ethproto import w3wrappers, wrappers

    wrappers.DEFAULT_PROVIDER = "w3"
    w3wrappers.CONTRACT_JSON_PATH = ["tests/hardhat-project"]
    os.environ["WEB3_PROVIDER_URI"] = "http://localhost:5350"


@pytest.fixture(scope="module", autouse=True)
def reset_provider():
    """Resets the provider for each module. Mainly for addressbook and contract map cleanse"""
    if os.environ.get("TEST_ENV", None) == "web3py":
        from web3 import Web3

        from ethproto import w3wrappers, wrappers

        wrappers.register_provider("w3", w3wrappers.W3Provider(Web3()))
        yield
        wrappers.register_provider("w3", w3wrappers.W3Provider(Web3()))
        return
    yield


# @pytest.fixture(autouse=True, scope="session")
# def hardhat_compile():
