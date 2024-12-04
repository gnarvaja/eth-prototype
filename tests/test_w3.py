import os

import pytest
from web3 import Web3

from ethproto import w3wrappers, wrappers

pytestmark = [
    pytest.mark.skipif(os.environ.get("TEST_ENV", None) != "web3py", reason="web3py-only tests"),
    pytest.mark.usefixtures("local_node_provider"),
]


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
    counter = contract_class(initial_value=0, owner="owner")
    assert counter.value() == 0
    counter.increase()
    assert counter.value() == 1


class Datatypes(wrappers.ETHWrapper):
    eth_contract = "Datatypes"

    echoAddress = wrappers.MethodAdapter((("address", "address"),), "address")


def test_address_arguments():
    from eth_account import Account

    wrapper = Datatypes(owner="owner")

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

    counter = wrapper(initialValue=0, owner="owner")
    assert counter.value() == 0
    counter.increase()
    assert counter.value() == 1


def test_get_events():
    provider = wrappers.get_provider("w3")
    contract_def = provider.get_contract_def("EventLauncher")
    wrapper = wrappers.ETHWrapper.build_from_def(contract_def)

    launcher = wrapper(owner="owner")

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


@pytest.fixture
def sign_and_send(mocker, hardhat_node):
    """Sets up sign-and-send transact mode with a well-known address, returns the address"""
    mocker.patch("ethproto.w3wrappers.W3_TRANSACT_MODE", "sign-and-send")
    mocker.patch.dict(
        os.environ,
        {"W3_ADDR_HARDHAT_18": "0xde9be858da4a475276426320d5e9262ecfc3ba460bfac56360bfa6c4c28b4ee0"},
    )
    # Force recreate the provider and its address book after patching the environment
    w3wrappers.register_w3_provider("w3", Web3(Web3.HTTPProvider(hardhat_node)))
    return "0xdD2FD4581271e230360230F9337D5c0430Bf44C0"


def test_sign_and_send(sign_and_send):
    # Deploy a contract using sign-and-send
    wrapper = Datatypes(owner="HARDHAT_18")

    assert wrapper.echoAddress("HARDHAT_18") == "HARDHAT_18"
    assert wrappers.get_provider("w3").address_book.get_account("HARDHAT_18") == sign_and_send


def test_sign_and_send_upgradeable(sign_and_send):
    upgradeable = CounterUpgradeableWithLibrary(initial_value=0, owner="HARDHAT_18")
    assert upgradeable.value() == 0
    upgradeable.increase()
    assert upgradeable.value() == 1


def test_sign_and_send_interact_with_existing_contract(sign_and_send):
    counter = Counter(initial_value=0, owner="HARDHAT_18")
    assert counter.value() == 0  # sanity check

    connected = Counter.connect(counter.contract.address)

    # Interactions with the connected contract work as expected
    assert connected.value() == 0
    connected.increase()
    assert connected.value() == 1

    assert counter.value() == 1  # sanity check
