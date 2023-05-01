import os
import pytest


def test_dependencies():
    if os.environ.get("TEST_ENV", None) != "web3py":
        pytest.skip("Defender relay dependencies are only installed in web3 env")
    from ethproto import defender_relay
    assert defender_relay
