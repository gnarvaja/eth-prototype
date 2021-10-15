"""Base module for wrappers"""
from abc import ABC, abstractmethod
from functools import partial
from .wadray import Wad, Ray
from Crypto.Hash import keccak

MAXUINT256 = 2**256 - 1


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
            self._handle_exception(err)
        return self.unparse(self.eth_return_type, ret_value)

    @classmethod
    def _parse_keccak256(cls, value):
        if value.startswith("0x"):
            return value
        k = keccak.new(digest_bits=256)
        k.update(value.encode("utf-8"))
        return k.hexdigest()

    @classmethod
    def unparse(cls, value_type, value):
        if value_type == "amount":
            return Wad(value)
        if value_type == "ray":
            return Ray(value)
        if value_type == "address":
            return AddressBook.instance.get_name(value)
        return value


class IERC20Mixin:
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


class IERC721Mixin:
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
