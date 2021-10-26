"""Base module for wrappers"""
from abc import ABC, abstractmethod
from contextlib import contextmanager
from functools import partial
from .wadray import Wad, Ray
from environs import Env

env = Env()

SKIP_PROXY = env.bool("SKIP_PROXY", False)
DEFAULT_PROVIDER = env.str("DEFAULT_PROVIDER", None)

MAXUINT256 = 2**256 - 1

_providers = {}


def get_provider(provider_key=None):
    global DEFAULT_PROVIDER
    provider_key = provider_key or DEFAULT_PROVIDER
    if provider_key is None:
        if len(_providers) == 1:
            provider_key = next(iter(_providers.keys()))
        else:
            raise RuntimeError("No provider installed or no default provider specified")
    return _providers[provider_key]


def register_provider(provider_key, provider):
    global _providers
    _providers[provider_key] = provider


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
        eth_call = instance.eth_call(
            self.eth_method, self.args, self.return_type, self.adapt_args,
            eth_variant=self.eth_variant
        )
        if self.is_property:
            return eth_call(instance)
        return partial(eth_call, instance)

    def __set__(self, instance, value):
        if not self.is_property:
            raise NotImplementedError()
        eth_call = instance.eth_call(self.set_eth_method, (("new_value", self.return_type), ))
        return eth_call(instance, value)


class AddressBook(ABC):
    ZERO = "0x0000000000000000000000000000000000000000"

    @abstractmethod
    def get_account(self, name):
        raise NotImplementedError()

    @abstractmethod
    def get_name(self, account_or_address):
        raise NotImplementedError()

    @classmethod
    def set_instance(cls, obj):
        cls.instance = obj


class ETHCall(ABC):
    def __init__(self, eth_method, eth_args, eth_return_type="", adapt_args=None, eth_variant=None):
        self.eth_method = eth_method
        self.eth_args = eth_args
        self.eth_return_type = eth_return_type
        self.adapt_args = adapt_args
        self.eth_variant = eth_variant

    @abstractmethod
    def _get_eth_function(self, wrapper, eth_method, eth_variant=None):
        raise NotImplementedError()

    def _handle_exception(self, err):
        raise err

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
                msg_args["from"] = self.parse(wrapper, "address", arg_value)
            elif arg_type == "msg.value":
                msg_args["value"] = self.parse(wrapper, "amount", arg_value)
            else:
                call_args.append(self.parse(wrapper, arg_type, arg_value))

        if "from" not in msg_args and hasattr(wrapper, "_auto_from"):
            msg_args["from"] = wrapper._auto_from
        call_args.append(msg_args)

        eth_function = self._get_eth_function(wrapper, self.eth_method, self.eth_variant)

        try:
            ret_value = eth_function(*call_args)
        except Exception as err:
            self._handle_exception(err)
        return self.unparse(wrapper, self.eth_return_type, ret_value)

    @classmethod
    def parse_args(cls, wrapper, eth_args, *args, **kwargs):
        """Used as helper for parsing arguments, for example for constructor"""
        call_args = []
        msg_args = {}
        for i, (arg_name, arg_type) in enumerate(eth_args):
            if i < len(args):
                arg_value = args[i]
            elif arg_name in kwargs:
                arg_value = kwargs[arg_name]
            else:
                raise TypeError(f"missing required argument: '{arg_name}'")
            if arg_type == "msg.sender":
                msg_args["from"] = cls.parse(wrapper, "address", arg_value)
            elif arg_type == "msg.value":
                msg_args["value"] = cls.parse(wrapper, "amount", arg_value)
            else:
                call_args.append(cls.parse(wrapper, arg_type, arg_value))
        return call_args, msg_args

    @classmethod
    def _parse_keccak256(cls, value):
        from Crypto.Hash import keccak  # To avoid import of wrappers breaks if keccak not installed
        if value.startswith("0x"):
            return value
        k = keccak.new(digest_bits=256)
        k.update(value.encode("utf-8"))
        return k.hexdigest()

    @classmethod
    def unparse(cls, wrapper, value_type, value):
        if value_type == "amount":
            return Wad(value)
        if value_type == "ray":
            return Ray(value)
        if value_type == "address":
            return wrapper.provider.address_book.get_name(value)
        return value


class ETHWrapper:
    proxy_kind = None
    libraries_required = []
    constructor_args = None

    def __init__(self, owner="owner", *init_params, **kwargs):
        self.provider_key = kwargs.get("provider_key", None)
        if self.constructor_args is not None:
            init_params, transaction_kwargs = self.eth_call.parse_args(
                self, self.constructor_args, *init_params, **kwargs
            )
            if transaction_kwargs:
                kwargs.update(transaction_kwargs)
        self.provider.init_eth_wrapper(self, owner, init_params, kwargs)
        self._auto_from = self.owner

    @property
    def provider(self):
        return get_provider(self.provider_key)

    @property
    def eth_call(self):
        return self.provider.eth_call

    @classmethod
    def connect(cls, contract, owner=None, provider_key=None):
        """Connects a wrapper to an existing deployed object"""
        provider = get_provider(provider_key)
        if isinstance(contract, str):  # It's an address
            contract_factory = provider.get_contract_factory(cls.eth_contract)
            contract = provider.build_contract(contract, contract_factory, cls.eth_contract)
        return cls.build_from_contract(contract, owner, provider_key)

    @classmethod
    def build_from_contract(cls, contract, owner=None, provider_key=None):
        obj = cls.__new__(cls)
        obj.provider_key = provider_key
        obj.contract = contract
        obj.owner = get_provider(provider_key).address_book.get_account(owner)
        obj._auto_from = obj.owner
        return obj

    @property
    def contract_id(self):
        return self.contract.address

    def _get_account(self, name):
        return self.provider.address_book.get_account(name)

    def _get_name(self, account):
        return self.provider.address_book.get_name(account)

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
