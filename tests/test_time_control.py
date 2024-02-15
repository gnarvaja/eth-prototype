import os

import pytest

from ethproto import wrappers


@pytest.mark.skipif(os.environ.get("TEST_ENV", None) != "web3py", reason="web3py-only test")
def test_timecontrol():
    from ethproto.w3wrappers import W3Provider

    provider = wrappers.get_provider()
    assert isinstance(provider, W3Provider)
    time_control = provider.time_control

    initial_timestamp = time_control.now
    time_control.fast_forward(100)

    assert time_control.now == initial_timestamp + 100
