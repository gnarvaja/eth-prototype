from ethproto import wrappers
from ethproto.w3wrappers import W3Provider


def test_timecontrol():
    provider = wrappers.get_provider()
    assert isinstance(provider, W3Provider)
    time_control = provider.time_control

    initial_timestamp = time_control.now
    time_control.fast_forward(100)

    assert time_control.now == initial_timestamp + 100
