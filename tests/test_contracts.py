from functools import partial
from unittest import TestCase

import pytest
from environs import Env
from m9g.fields import IntField

from ethproto import wrappers
from ethproto.contracts import (
    Contract,
    ERC20Token,
    ERC721Token,
    RevertError,
    WadField,
    external,
    view,
)
from ethproto.wadray import _W, Wad

env = Env()

TEST_ENV = env.list("TEST_ENV", ["pure-python"])

pytestmark = pytest.mark.usefixtures("local_node_provider")


class TestCurrency(wrappers.IERC20):
    eth_contract = "TestCurrency"
    __test__ = False

    constructor_args = (("name", "string"), ("symbol", "string"), ("initial_supply", "amount"))

    def __init__(self, owner="owner", name="Test Currency", symbol="TEST", initial_supply=Wad(0), **kwargs):
        super().__init__(owner, name, symbol, initial_supply, **kwargs)

    mint = wrappers.MethodAdapter((("recipient", "address"), ("amount", "amount")))
    burn = wrappers.MethodAdapter((("recipient", "address"), ("amount", "amount")))

    @property
    def balances(self):
        return dict(
            (name, self.balance_of(name))
            for name, address in self.provider.address_book.name_to_address.items()
        )


class TestCurrencyUUPS(TestCurrency):
    proxy_kind = "uups"
    eth_contract = "TestCurrencyUUPS"

    constructor_args = ()
    initialize_args = (("name", "string"), ("symbol", "string"), ("initial_supply", "amount"))


class TestNFT(wrappers.IERC721):
    __test__ = False

    eth_contract = "TestNFT"

    def __init__(self, owner="owner", name="Test NFT", symbol="NFTEST", **kwargs):
        super().__init__(owner, name, symbol, **kwargs)

    mint = wrappers.MethodAdapter((("to", "address"), ("token_id", "int")))
    burn = wrappers.MethodAdapter((("owner", "msg.sender"), ("token_id", "int")))


class MyTestContract(Contract):
    counter = IntField(default=10)
    amount = WadField(default=_W(0))

    @external
    def inc_counter(self, qty):
        self.counter += qty
        if qty <= 0:
            raise RevertError("qty cannot be equal or less than zero")

    @external
    def inc_amount(self, amount):
        self.amount += amount
        if amount <= _W(0):
            raise RevertError("amount cannot be equal or less than zero")

    @view
    def bad_view(self):
        self.counter += 1

    @view
    def bad_view_two(self):
        self.inc_counter(5)

    @view
    def good_view(self):
        return self.amount


class TestReversion(TestCase):
    def test_revert_rolls_back_changes(self):
        tcontract = MyTestContract()
        assert tcontract.counter == 10
        assert tcontract.amount == _W(0)

        tcontract.inc_counter(5)
        assert tcontract.counter == 15

        with pytest.raises(RevertError):
            tcontract.inc_counter(-5)

        assert tcontract.counter == 15

        tcontract.inc_amount(_W(5))
        assert tcontract.amount == _W(5)

        with pytest.raises(RevertError):
            tcontract.inc_amount(_W(-5))

        assert tcontract.amount == _W(5)

    def test_view_cannot_modify(self):
        tcontract = MyTestContract()
        with pytest.raises(AssertionError, match="Contract .* modified in view"):
            tcontract.bad_view()

    def test_view_cannot_call_external(self):
        tcontract = MyTestContract()
        with pytest.raises(RuntimeError):
            tcontract.bad_view_two()


def _connected_contract(eth_wrapper_class, *args, **kwargs):
    "Constructs (deploys) a wrapper but then reconnects to deployed address"
    eth_wrapper = eth_wrapper_class(*args, **kwargs)
    return eth_wrapper_class.connect(eth_wrapper.contract, eth_wrapper.owner, eth_wrapper.provider_key)


def _connected_contract_address(eth_wrapper_class, *args, **kwargs):
    eth_wrapper = eth_wrapper_class(*args, **kwargs)
    return eth_wrapper_class.connect(
        eth_wrapper.contract.address, eth_wrapper.owner, eth_wrapper.provider_key
    )


ERC20TokenAlternatives = [ERC20Token]

if "web3py" in TEST_ENV:
    ERC20TokenAlternatives.append(partial(TestCurrency, provider_key="w3"))
    ERC20TokenAlternatives.append(partial(_connected_contract, TestCurrency, provider_key="w3"))
    ERC20TokenAlternatives.append(partial(TestCurrencyUUPS, provider_key="w3"))


@pytest.mark.parametrize("token_class", ERC20TokenAlternatives)
class TestERC20Token:
    def _validate_total_supply(self, token):
        "Validates total_supply equals to the sum of all users balances"
        if self._is_w3(token):
            return  # Avoid if is_w3
        total_supply = token.total_supply()
        total_supply_calculated = sum(token.balances.values(), _W(0))
        assert total_supply == total_supply_calculated

    def test_total_supply(self, token_class):
        token = token_class(owner="owner", name="TEST", symbol="TEST", initial_supply=_W(1000))
        assert token.total_supply() == _W(1000)
        assert token.balance_of("owner") == _W(1000)
        self._validate_total_supply(token)

        token.mint("LP1", _W(200))
        assert token.balance_of("LP1") == _W(200)
        assert token.total_supply() == _W(1200)
        self._validate_total_supply(token)

        token.burn("owner", _W(100))
        assert token.total_supply() == _W(1100)

        with pytest.raises(RevertError):
            token.burn("owner", _W(1000))

    def _is_w3(self, token):
        if isinstance(token, wrappers.IERC20) and "W3" in token.provider.__class__.__name__:
            return True
        return False

    def test_transfer(self, token_class):
        token = token_class(owner="owner", name="TEST", symbol="TEST", initial_supply=_W(1000))
        token.transfer("owner", "Guillo", _W(400))
        assert token.balance_of("owner") == _W(600)
        assert token.balance_of("Guillo") == _W(400)
        self._validate_total_supply(token)

        with pytest.raises(RevertError):
            token.transfer("Guillo", "Marco", _W(450))

        assert token.balance_of("Guillo") == _W(400)  # unchanged
        token.transfer("owner", "Marco", _W(600))
        assert token.balance_of("owner") == _W(0)
        assert token.balance_of("Marco") == _W(600)
        assert token.total_supply() == _W(1000)
        self._validate_total_supply(token)

    def test_approve_flow(self, token_class):
        token = token_class(owner="owner", name="TEST", symbol="TEST", initial_supply=_W(2000))
        token.approve("owner", "Spender", _W(500))
        if hasattr(token, "last_receipt"):
            assert "Approval" in token.last_receipt.events
            assert token.last_receipt.events["Approval"]["value"] == _W(500)
        assert token.allowance("owner", "Spender") == _W(500)

        token.transfer_from("Spender", "owner", "Guillo", _W(200))
        assert token.balance_of("Guillo") == _W(200)
        assert token.balance_of("owner") == _W(1800)
        assert token.allowance("owner", "Spender") == _W(300)

        with pytest.raises(RevertError):
            token.transfer_from("Spender", "owner", "Luca", _W(400))

        token.transfer_from("Spender", "owner", "Giacomo", _W(300))
        assert token.allowance("owner", "Spender") == _W(0)

        with pytest.raises(RevertError):
            token.transfer_from("Spender", "owner", "Luca", _W(1))

        assert token.balance_of("Guillo") == _W(200)
        assert token.balance_of("owner") == _W(1500)
        assert token.balance_of("Giacomo") == _W(300)
        assert token.balance_of("Luca") == _W(0)


ERC721TokenAlternatives = [ERC721Token]
if "web3py" in TEST_ENV:
    ERC721TokenAlternatives.append(partial(TestNFT, provider_key="w3"))


@pytest.mark.parametrize("token_class", ERC721TokenAlternatives)
class TestERC721Token:
    def test_mint_burn(self, token_class):
        nft = token_class(owner="owner", name="TEST", symbol="TEST")

        nft.mint("CUST1", 1234)
        assert nft.balance_of("CUST1") == 1
        nft.mint("CUST1", 1235)
        assert nft.balance_of("CUST1") == 2
        assert nft.owner_of(1234) == "CUST1"
        assert nft.owner_of(1235) == "CUST1"
        nft.burn("CUST1", 1235)
        assert nft.balance_of("CUST1") == 1
        with pytest.raises(RevertError, match="ERC721: invalid token ID"):
            nft.owner_of(1235)
        nft.burn("CUST1", 1234)
        assert nft.balance_of("CUST1") == 0

    def test_transfer(self, token_class):
        nft = token_class(owner="owner", name="TEST", symbol="TEST")

        nft.mint("CUST1", 1234)
        assert nft.balance_of("CUST1") == 1
        assert nft.owner_of(1234) == "CUST1"
        nft.transfer_from("CUST1", "CUST1", "CUST2", 1234)
        assert nft.balance_of("CUST1") == 0
        assert nft.balance_of("CUST2") == 1
        assert nft.owner_of(1234) == "CUST2"

    def test_approve_transfer(self, token_class):
        nft = token_class(owner="owner", name="TEST", symbol="TEST")

        nft.mint("CUST1", 1234)
        assert nft.balance_of("CUST1") == 1
        assert nft.owner_of(1234) == "CUST1"
        nft.approve("CUST1", "SPEND", 1234)
        assert nft.get_approved(1234) == "SPEND"

        nft.transfer_from("SPEND", "CUST1", "CUST2", 1234)
        assert nft.balance_of("CUST1") == 0
        assert nft.balance_of("CUST2") == 1
        assert nft.owner_of(1234) == "CUST2"

    def test_approve_for_all(self, token_class):
        nft = token_class(owner="owner", name="TEST", symbol="TEST")

        nft.mint("CUST1", 1234)
        nft.mint("CUST1", 1235)
        nft.mint("CUST1", 1236)
        assert nft.balance_of("CUST1") == 3
        assert not nft.is_approved_for_all("CUST1", "SPEND")
        nft.set_approval_for_all("CUST1", "SPEND", True)
        assert nft.is_approved_for_all("CUST1", "SPEND")

        nft.transfer_from("SPEND", "CUST1", "CUST2", 1234)
        assert nft.balance_of("CUST1") == 2
        assert nft.balance_of("CUST2") == 1

        with pytest.raises(RevertError):
            nft.transfer_from("SPEND", "CUST2", "CUST3", 1236)
        nft.transfer_from("SPEND", "CUST1", "CUST2", 1236)
        assert nft.owner_of(1234) == "CUST2"
        assert nft.owner_of(1236) == "CUST2"
        assert nft.owner_of(1235) == "CUST1"
        assert nft.balance_of("CUST1") == 1
        assert nft.balance_of("CUST2") == 2
        nft.set_approval_for_all("CUST1", "SPEND", False)

        with pytest.raises(RevertError, match="ERC721: caller is not token owner or approved"):
            nft.transfer_from("SPEND", "CUST1", "CUST2", 1235)
