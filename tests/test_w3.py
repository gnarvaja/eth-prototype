import os

import pytest

from ethproto import wrappers

pytestmark = pytest.mark.skipif(os.environ.get("TEST_ENV", None) != "web3py", reason="web3py-only tests")


class Counter(wrappers.ETHWrapper):
    eth_contract = "Counter"
    # libraries_required = []

    constructor_args = (("initial_value", "int"),)

    def __init__(self, initial_value, **kwargs):
        super().__init__(initial_value=initial_value, **kwargs)

    increase = wrappers.MethodAdapter()
    value = wrappers.MethodAdapter((), "int")


class CounterWithLibrary(Counter):
    eth_contract = "CounterWithLibrary"


class CounterUpgradeableWithLibrary(Counter):
    eth_contract = "CounterUpgradeableWithLibrary"
    proxy_kind = "uups"
    constructor_args = ()
    initialize_args = (("initial_value", "int"),)


@pytest.mark.parametrize("contract_class", [Counter, CounterWithLibrary, CounterUpgradeableWithLibrary])
def test_deploy_counter(contract_class):
    counter = contract_class(initial_value=0)
    assert counter.value() == 0
    counter.increase()
    assert counter.value() == 1


class Datatypes(wrappers.ETHWrapper):
    eth_contract = "Datatypes"

    echoAddress = wrappers.MethodAdapter((("address", "address"),), "address")


def test_address_arguments():
    from eth_account import Account

    wrapper = Datatypes()

    account = Account.create("TEST TEST TEST")

    # Supports string addresses
    assert wrapper.echoAddress(account.address) == account.address

    # Supports Account objects
    assert wrapper.echoAddress(account) == account.address

    # Supports named accounts and they're converted back on response
    assert wrapper.echoAddress("owner") == "owner"

    # Supports ETHWrapper objects
    assert wrapper.echoAddress(wrapper) == wrapper.contract.address

    # Supports Contract objects
    assert wrapper.echoAddress(wrapper.contract) == wrapper.contract.address


def test_wrapper_build_from_def():
    provider = wrappers.get_provider("w3")
    contract_def = provider.get_contract_def("Counter")
    wrapper = wrappers.ETHWrapper.build_from_def(contract_def)

    counter = wrapper(initialValue=0)
    assert counter.value() == 0
    counter.increase()
    assert counter.value() == 1


def test_get_events():
    provider = wrappers.get_provider("w3")
    contract_def = provider.get_contract_def("EventLauncher")
    wrapper = wrappers.ETHWrapper.build_from_def(contract_def)

    launcher = wrapper()

    launcher.launchEvent1(1)

    cutoff_block = provider.w3.eth.get_block("latest")
    launcher.launchEvent2(2)
    launcher.launchEvent1(3)

    all_event1 = provider.get_events(launcher, "Event1", dict(from_block=0))
    assert len(all_event1) == 2

    first_event1_only = provider.get_events(launcher, "Event1", dict(to_block=cutoff_block.number))
    assert len(first_event1_only) == 1
    assert first_event1_only[0] == all_event1[0]

    last_event1_only = provider.get_events(launcher, "Event1", dict(from_block=cutoff_block.number + 1))
    assert len(last_event1_only) == 1
    assert last_event1_only[0] == all_event1[-1]

    event2 = provider.get_events(launcher, "Event2")
    assert len(event2) == 1
    assert event2[0].args.value == 2
