import os
import json
from contextlib import contextmanager
from .contracts import RevertError
from ._wrappers import MethodAdapter, IERC20Mixin, IERC721Mixin, ETHCall, AddressBook, MAXUINT256
from environs import Env
import eth_utils
from eth_account.account import Account, LocalAccount

w3 = None  # Must be initialized from outside

env = Env()

CONTRACT_JSON_PATH = env.list("CONTRACT_JSON_PATH", [], delimiter=":")
SKIP_PROXY = os.getenv("SKIP_PROXY", "F") in ("T", "1")
contract_def_cache = {}


class TimeControl:
    def fast_forward(self, secs):
        w3.provider.make_request("evm_increaseTime", [secs])
        # Not tested!

    @property
    def now(self):
        return w3.get_block("latest").timestamp


time_control = TimeControl()


def get_contract_def(eth_contract):
    global contract_def_cache

    if eth_contract not in contract_def_cache:
        json_file = None
        for contract_path in CONTRACT_JSON_PATH:
            if os.path.exists(os.path.join(contract_path, f"{eth_contract}.json")):
                json_file = os.path.join(contract_path, f"{eth_contract}.json")
                break
        else:
            raise RuntimeError(f"{eth_contract} JSON definition not found in {CONTRACT_JSON_PATH}")
        contract_def_cache[eth_contract] = json.load(open(json_file))
    return contract_def_cache[eth_contract]


def get_contract_factory(eth_contract):
    contract_def = get_contract_def(eth_contract)
    return w3.eth.contract(abi=contract_def["abi"], bytecode=contract_def.get("bytecode", None))


class W3AddressBook(AddressBook):
    def __init__(self, eth_accounts=None):
        self._eth_accounts = eth_accounts
        self.name_to_address = {}
        self.last_account_used = -1

    @property
    def eth_accounts(self):
        if self._eth_accounts is None:
            self._eth_accounts = w3.eth.accounts
        return self._eth_accounts

    def get_account(self, name):
        if isinstance(name, (Account, LocalAccount)):
            return name
#        if isinstance(name, (Contract, ProjectContract)):
#            return name
        if name is None:
            return self.ZERO
        if type(name) == str and name.startswith("0x"):
            return name
        if name not in self.name_to_address:
            self.last_account_used += 1
            try:
                self.name_to_address[name] = self.eth_accounts[self.last_account_used]
            except IndexError:
                self.name_to_address[name] = w3.eth.account.create().address
        return self.name_to_address[name]

    def get_name(self, account_or_address):
        if isinstance(account_or_address, (LocalAccount, )):
            account_or_address = account_or_address.address

        for name, addr in self.name_to_address.items():
            if addr == account_or_address:
                return name
        return None


AddressBook.set_instance(W3AddressBook())


class W3ETHCall(ETHCall):
    def _find_function_abi(self, contract, eth_method, eth_variant):
        abis = [x for x in contract.abi if "name" in x and x["name"] == eth_method]
        if len(abis) == 1:
            return abis[0]
        # TODO: eth_variant
        raise RuntimeError(f"Method {eth_method} not found")

    def _get_eth_function(self, wrapper, eth_method, eth_variant=None):
        function = getattr(wrapper.contract.functions, eth_method)  # TODO: eth_variant
        function_abi = self._find_function_abi(wrapper.contract, eth_method, eth_variant)
        if function_abi["stateMutability"] in ("pure", "view"):
            def eth_function(*args):
                if args and type(args[-1]) == dict:
                    args = args[:-1]  # remove dict with {from: ...}
                return function(*args).call()
        else:  # Mutable function, need to send and wait transaction
            def eth_function(*args):
                if args and type(args[-1]) == dict:
                    transact_args = args[-1]
                    args = args[:-1]  # remove dict with {from: ...}
                else:
                    transact_args = None  # Will use default_account??
                if transact_args:
                    tx_hash = function(*args).transact(transact_args)
                else:
                    tx_hash = function(*args).transact()
                return w3.eth.wait_for_transaction_receipt(tx_hash)

        return eth_function

    def _handle_exception(self, err):
        if str(err).startswith("execution reverted: "):
            raise RevertError(str(err)[len("execution reverted: "):])
        super()._handle_exception(err)

    @classmethod
    def parse(cls, value_type, value):
        if value_type == "address":
            if isinstance(value, (LocalAccount, Account)):
                return value
#            elif isinstance(value, (Contract, ProjectContract)):
#                return value.address
            elif isinstance(value, ETHWrapper):
                return value.contract.address
            elif isinstance(value, str) and value.startswith("0x"):
                return value
            return AddressBook.instance.get_account(value)
        if value_type == "keccak256":
            return cls._parse_keccak256(value)
        if value_type == "contract":
            if isinstance(value, ETHWrapper):
                return value.contract.address
            elif value is None:
                return AddressBook.ZERO
            raise RuntimeError(f"Invalid contract: {value}")
        if value_type == "amount" and value is None:
            return MAXUINT256
        return value


def encode_function_data(initializer=None, *args):
    """Encodes the function call so we can work with an initializer.
    Args:
        initializer ([brownie.network.contract.ContractTx], optional):
        The initializer function we want to call. Example: `box.store`.
        Defaults to None.
        args (Any, optional):
        The arguments to pass to the initializer function
    Returns:
        [bytes]: Return the encoded bytes.
    """
    if len(args) == 0 or not initializer:
        return eth_utils.to_bytes(hexstr="0x")
    else:
        return initializer.encode_input(*args)


class ETHWrapper:
    proxy_kind = None
    libraries_required = []
    eth_call = W3ETHCall

    def __init__(self, owner="owner", *init_params):
        self.owner = AddressBook.instance.get_account(owner)
        for library in self.libraries_required:
            get_contract_factory(library).deploy({"from": self.owner})
        eth_contract = get_contract_factory(self.eth_contract)
        if self.proxy_kind is None:
            self.contract = self.construct(eth_contract, init_params, {"from": self.owner})
        elif self.proxy_kind == "uups" and not SKIP_PROXY:
            real_contract = self.construct(eth_contract, init_params, {"from": self.owner})
            ERC1967Proxy = get_contract_factory("ERC1967Proxy")
            proxy_contract = self.construct(
                ERC1967Proxy,
                (real_contract.address, encode_function_data(real_contract.functions.initialize,
                                                             *init_params)),
                {"from": self.owner}
            )
            self.contract = w3.eth.contract(abi=eth_contract.abi, address=proxy_contract.address)
        elif self.proxy_kind == "uups" and SKIP_PROXY:
            self.contract = self.construct(eth_contract, (), {"from": self.owner})
            # TODO
            self.contract.functions.initialize(*init_params, {"from": self.owner})

    @staticmethod
    def construct(contract_factory, constructor_args=(), transact_kwargs={}):
        tx_hash = contract_factory.constructor(*constructor_args).transact(transact_kwargs)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        # TODO: verify receipt OK
        return w3.eth.contract(abi=contract_factory.abi, address=receipt.contractAddress)

    @classmethod
    def connect(cls, contract, owner=None):
        """Connects a wrapper to an existing deployed object"""
        obj = cls.__new__(cls)
        if isinstance(contract, str):
            eth_contract = get_contract_factory(cls.eth_contract)
            contract = Contract.from_abi(cls.eth_contract, contract, eth_contract.abi)
        obj.contract = contract
        obj.owner = owner
        return obj

    @property
    def contract_id(self):
        return self.contract.address

    def _get_account(self, name):
        return AddressBook.instance.get_account(name)

    def _get_name(self, account):
        return AddressBook.instance.get_name(account)

    grant_role = MethodAdapter((("role", "keccak256"), ("user", "address")))

    @contextmanager
    def as_(self, user):
        prev_auto_from = getattr(self, "_auto_from", "missing")
        self._auto_from = self._get_account(user)
        try:
            yield self
        finally:
            if prev_auto_from == "missing":
                del self._auto_from
            else:
                self._auto_from = prev_auto_from


class IERC20(IERC20Mixin, ETHWrapper):
    pass


class IERC721(IERC721Mixin, ETHWrapper):
    pass
