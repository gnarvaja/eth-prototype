import os
import json
from contextlib import contextmanager
from functools import partial
from .contracts import RevertError
from .wadray import Wad, Ray
from environs import Env
from Crypto.Hash import keccak
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


class AddressBook:
    ZERO = "0x0000000000000000000000000000000000000000"

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


AddressBook.instance = AddressBook()

MAXUINT256 = 2**256 - 1


class ETHCall:
    def __init__(self, eth_method, eth_args, eth_return_type="", adapt_args=None, eth_variant=None):
        self.eth_method = eth_method
        self.eth_args = eth_args
        self.eth_return_type = eth_return_type
        self.adapt_args = adapt_args
        self.eth_variant = eth_variant

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

    def __call__(self, wrapper, *args, **kwargs):
        call_args = []
        msg_args = {}

        if self.adapt_args:
            args, kwargs = self.adapt_args(args, kwargs)

        for i, (arg_name, arg_type) in enumerate(self.eth_args):
            if i < len(args):
                arg_value = args[i]
            elif arg_name in kwargs:
                arg_value = kwargs[arg_name]
            else:
                raise TypeError(f"{self.eth_method}() missing required argument: '{arg_name}'")
            if arg_type == "msg.sender":
                msg_args["from"] = self.parse("address", arg_value)
            elif arg_type == "msg.value":
                msg_args["value"] = self.parse("amount", arg_value)
            else:
                call_args.append(self.parse(arg_type, arg_value))

        if "from" not in msg_args and hasattr(wrapper, "_auto_from"):
            msg_args["from"] = wrapper._auto_from
        call_args.append(msg_args)

        eth_function = self._get_eth_function(wrapper, self.eth_method, self.eth_variant)

        try:
            ret_value = eth_function(*call_args)
        except Exception as err:
            if str(err).startswith("execution reverted: "):
                raise RevertError(str(err)[len("execution reverted: "):])
            raise
        return self.unparse(self.eth_return_type, ret_value)

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
            if not value.startswith("0x"):
                k = keccak.new(digest_bits=256)
                k.update(value.encode("utf-8"))
                return k.hexdigest()
        if value_type == "contract":
            if isinstance(value, ETHWrapper):
                return value.contract.address
            elif value is None:
                return AddressBook.ZERO
            raise RuntimeError(f"Invalid contract: {value}")
        if value_type == "amount" and value is None:
            return MAXUINT256
        return value

    @classmethod
    def unparse(cls, value_type, value):
        if value_type == "amount":
            return Wad(value)
        if value_type == "ray":
            return Ray(value)
        if value_type == "address":
            return AddressBook.instance.get_name(value)
        return value


class MethodAdapter:
    def __init__(self, args=(), return_type="", eth_method=None, adapt_args=None, is_property=False,
                 set_eth_method=None, eth_variant=None):
        self.eth_method = eth_method
        self.set_eth_method = set_eth_method
        self.return_type = return_type
        self.args = args
        self.adapt_args = adapt_args
        self.is_property = is_property
        self.eth_variant = eth_variant

    def __set_name__(self, owner, name):
        self._method_name = name
        if self.eth_method is None:
            self.eth_method = self.snake_to_camel(name)
        if self.set_eth_method is None:
            self.set_eth_method = "set" + self.eth_method[0].upper() + self.eth_method[1:]

    @staticmethod
    def snake_to_camel(name):
        components = name.split('_')
        return components[0] + ''.join(x.title() for x in components[1:])

    @property
    def method_name(self):
        return self._method_name or self.eth_method

    def __get__(self, instance, owner=None):
        eth_call = ETHCall(self.eth_method, self.args, self.return_type, self.adapt_args,
                           eth_variant=self.eth_variant)
        if self.is_property:
            return eth_call(instance)
        return partial(eth_call, instance)

    def __set__(self, instance, value):
        if not self.is_property:
            raise NotImplementedError()
        eth_call = ETHCall(self.set_eth_method, (("new_value", self.return_type), ))
        return eth_call(instance, value)


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


class IERC20(ETHWrapper):
    eth_contract = "IERC20Metadata"

    name = MethodAdapter((), "string", is_property=True)
    symbol = MethodAdapter((), "string", is_property=True)
    decimals = MethodAdapter((), "int", is_property=True)
    total_supply = MethodAdapter((), "amount")
    balance_of = MethodAdapter((("account", "address"), ), "amount")
    transfer = MethodAdapter((
        ("sender", "msg.sender"), ("recipient", "address"), ("amount", "amount")
    ), "bool")

    allowance = MethodAdapter((("owner", "address"), ("spender", "address")), "amount")
    approve = MethodAdapter((("owner", "msg.sender"), ("spender", "address"), ("amount", "amount")),
                            "bool")
    increase_allowance = MethodAdapter(
        (("owner", "msg.sender"), ("spender", "address"), ("amount", "amount"))
    )
    decrease_allowance = MethodAdapter(
        (("owner", "msg.sender"), ("spender", "address"), ("amount", "amount"))
    )

    transfer_from = MethodAdapter((
        ("spender", "msg.sender"), ("sender", "address"), ("recipient", "address"), ("amount", "amount")
    ), "bool")


class IERC721(ETHWrapper):
    name = MethodAdapter((), "string", is_property=True)
    symbol = MethodAdapter((), "string", is_property=True)
    total_supply = MethodAdapter((), "int")
    balance_of = MethodAdapter((("account", "address"), ), "int")
    owner_of = MethodAdapter((("token_id", "int"), ), "address")
    approve = MethodAdapter((
        ("sender", "msg.sender"), ("spender", "address"), ("token_id", "int")
    ), "bool")
    get_approved = MethodAdapter((("token_id", "int"), ), "address")
    set_approval_for_all = MethodAdapter((
        ("sender", "msg.sender"), ("operator", "address"), ("approved", "bool")
    ))
    is_approved_for_all = MethodAdapter((("owner", "address"), ("operator", "address")), "bool")
    transfer_from = MethodAdapter((
        ("spender", "msg.sender"), ("from", "address"), ("to", "address"), ("token_id", "int")
    ), "bool")
    transfer = MethodAdapter((
        ("sender", "msg.sender"), ("recipient", "address"), ("amount", "amount")
    ), "bool")
