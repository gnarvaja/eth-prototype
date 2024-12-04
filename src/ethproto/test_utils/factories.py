from random import randint

import factory
import faker
from eth_abi import encode
from eth_typing import HexAddress
from eth_utils import function_signature_to_4byte_selector, to_checksum_address
from faker.providers import BaseProvider
from hexbytes import HexBytes
from web3.constants import ADDRESS_ZERO

from ethproto import aa_bundler


class EthProvider(BaseProvider):
    """
    A Provider for Ethereum related data
    >>> from faker import Faker
    >>> fake = Faker()
    >>> fake.add_provider(EthProvider)
    """

    def eth_address(self):
        ret = hex(randint(0, 2**160 - 1))
        if len(ret) < 42:
            ret = "0x" + "0" * (42 - len(ret)) + ret[2:]
        return to_checksum_address(ret)

    def eth_hash(self):
        ret = hex(randint(0, 2**256 - 1))
        if len(ret) < 66:
            return "0x" + "0" * (66 - len(ret)) + ret[2:]
        return ret


fake = faker.Faker()
fake.add_provider(EthProvider)
factory.Faker.add_provider(EthProvider)


class Tx(factory.Factory):
    class Meta:
        model = aa_bundler.Tx

    target = factory.Faker("eth_address")
    data = factory.LazyAttribute(
        lambda _: (
            function_signature_to_4byte_selector("balanceOf(address)")
            + encode(["address"], [fake.eth_address()])
        )
    )
    value = 0

    nonce_key: HexBytes = None
    nonce: int = None
    from_: HexAddress = ADDRESS_ZERO
    chain_id: int = None


class UserOperation(factory.Factory):
    class Meta:
        model = aa_bundler.UserOperation

    nonce = factory.Faker("random_int", min=0, max=2**256 - 1)

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        tx = Tx(from_=kwargs.pop("from_", fake.eth_address()))
        nonce = kwargs.pop("nonce")
        return model_class.from_tx(tx, nonce)
