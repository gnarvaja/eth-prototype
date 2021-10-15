import os
from contextlib import contextmanager
from .contracts import RevertError
from ._wrappers import MethodAdapter, IERC20Mixin, IERC721Mixin, ETHCall, AddressBook, MAXUINT256
from brownie import accounts
import eth_utils
import brownie
from brownie.network.account import Account, LocalAccount
from brownie.exceptions import VirtualMachineError
from brownie.network.state import Chain
from brownie.network.contract import Contract, ProjectContract

chain = Chain()

SKIP_PROXY = os.getenv("SKIP_PROXY", "F") in ("T", "1")


class TimeControl:
    def fast_forward(self, secs):
        chain.sleep(secs)
        chain.mine()

    @property
    def now(self):
        if len(chain) > 0:
            return chain[-1].timestamp
        return chain.time()


time_control = TimeControl()


def get_contract_factory(eth_contract):
    ret = getattr(brownie, eth_contract, None)
    if ret is not None:
        return ret
    # Might be a manually loaded project or an interface
    project = brownie.project.get_loaded_projects()[0]
    ret = getattr(project, eth_contract, None)
    if ret is not None:
        return ret
    return getattr(project.interface, eth_contract)


class BrownieAddressBook(AddressBook):

    def __init__(self, eth_accounts):
        self.eth_accounts = eth_accounts  # brownie.network.account.Accounts
        self.name_to_address = {}
        self.last_account_used = -1

    def get_account(self, name):
        if isinstance(name, (Account, LocalAccount)):
            return name
        if isinstance(name, (Contract, ProjectContract)):
            return name
        if name is None:
            return self.ZERO
        if name not in self.name_to_address:
            self.last_account_used += 1
            if (len(self.eth_accounts) - 1) > self.last_account_used:
                self.eth_accounts.add()
                self.name_to_address[name] = self.eth_accounts[self.last_account_used].address
        return self.eth_accounts.at(self.name_to_address[name])

    def get_name(self, account_or_address):
        if isinstance(account_or_address, Account):
            account_or_address = account_or_address.address

        for name, addr in self.name_to_address.items():
            if addr == account_or_address:
                return name
        return None


AddressBook.set_instance(BrownieAddressBook(accounts))


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


class BrownieETHCall(ETHCall):
    def _handle_exception(self, err):
        if isinstance(err, VirtualMachineError) and err.revert_type == "revert":
            raise RevertError(err.revert_msg)
        super()._handle_exception(err)

    def _get_eth_function(self, wrapper, eth_method, eth_variant=None):
        if eth_variant:
            return getattr(wrapper.contract, eth_method)[eth_variant]
        else:
            return getattr(wrapper.contract, eth_method)

    @classmethod
    def parse(cls, value_type, value):
        if value_type == "address":
            if isinstance(value, (LocalAccount, Account)):
                return value
            elif isinstance(value, (Contract, ProjectContract)):
                return value.address
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


class ETHWrapper:
    proxy_kind = None
    libraries_required = []
    eth_call = BrownieETHCall

    def __init__(self, owner="owner", *init_params):
        self.owner = AddressBook.instance.get_account(owner)
        for library in self.libraries_required:
            get_contract_factory(library).deploy({"from": self.owner})
        eth_contract = get_contract_factory(self.eth_contract)
        if self.proxy_kind is None:
            self.contract = eth_contract.deploy(*init_params, {"from": self.owner})
        elif self.proxy_kind == "uups" and not SKIP_PROXY:
            real_contract = eth_contract.deploy({"from": self.owner})
            proxy_contract = brownie.ERC1967Proxy.deploy(
                real_contract, encode_function_data(real_contract.initialize, *init_params),
                {"from": self.owner}
            )
            self.contract = Contract.from_abi(self.eth_contract, proxy_contract.address, eth_contract.abi)
        elif self.proxy_kind == "uups" and SKIP_PROXY:
            self.contract = eth_contract.deploy({"from": self.owner})
            self.contract.initialize(*init_params, {"from": self.owner})

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
