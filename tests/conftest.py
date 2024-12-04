import os

import pytest
from vcr import VCR
from web3.auto import w3
from web3.middleware import ExtraDataToPOAMiddleware

from ethproto.test_utils import hardhat, vcr_utils


def pytest_configure(config):
    if os.environ.get("TEST_ENV", None) != "web3py":
        return

    from ethproto import w3wrappers, wrappers

    wrappers.DEFAULT_PROVIDER = "w3"
    w3wrappers.CONTRACT_JSON_PATH = ["tests/hardhat-project"]


@pytest.fixture(scope="module")
def local_node_provider(hardhat_node):
    """Resets the provider for each module. Mainly for addressbook and contract map cleanse"""
    if os.environ.get("TEST_ENV", None) == "web3py":
        from web3 import Web3

        from ethproto import w3wrappers

        w3wrappers.register_w3_provider("w3", Web3(Web3.HTTPProvider(hardhat_node)))
        yield
        w3wrappers.register_w3_provider("w3", w3)
        return
    yield


@pytest.fixture(autouse=True, scope="session")
def w3_poa_middleware():
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)


def pytest_recording_configure(config, vcr: VCR):
    vcr.register_matcher("json_rpc", vcr_utils.json_rpc_matcher)
    vcr.before_record_request = vcr_utils.before_record_request


@pytest.fixture(autouse=True)
def vcr_config():
    return {
        "match_on": ["json_rpc"],
        "allow_playback_repeats": True,
        "allowed_hosts": ["localhost", "127.0.0.1", "::1"],
    }


@pytest.fixture(scope="session")
def hardhat_node():
    terminate_node = hardhat.hardhat_node("tests/hardhat-project", hostname="127.0.0.1", port=8545)
    try:
        yield "http://127.0.0.1:8545"
    finally:
        terminate_node()
