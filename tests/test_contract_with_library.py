from environs import Env
from ethproto import wrappers

# env = Env()


# TEST_ENV = env.list("TEST_ENV", ["pure-python"])


class Counter(wrappers.ETHWrapper):
    eth_contract = "Counter"
    libraries_required = []

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


def test_deploy_counter():
    counter = Counter(initial_value=0)
    assert counter.value() == 0
    counter.increase()
    assert counter.value() == 1


def test_deploy_counter_with_library():
    counter = CounterWithLibrary(initial_value=1)
    assert counter.value() == 1
    counter.increase()
    assert counter.value() == 2


def test_deploy_upgradeable_counter_with_library():
    counter = CounterUpgradeableWithLibrary(initial_value=0)
    assert counter.value() == 0
    counter.increase()
    assert counter.value() == 1
