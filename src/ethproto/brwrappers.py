from .contracts import RevertError
from .wrappers import ETHCall, AddressBook, MAXUINT256, SKIP_PROXY, ETHWrapper, BaseProvider
import eth_utils
from brownie import accounts
import brownie
from brownie.network.account import Account, LocalAccount
from brownie.exceptions import VirtualMachineError
from brownie.network.state import Chain
from brownie.network.contract import Contract, ProjectContract


class BrownieTimeControl:
    def __init__(self, chain=None):
        self.chain = chain or Chain()

    def fast_forward(self, secs):
        self.chain.sleep(secs)
        self.chain.mine()

    @property
    def now(self):
        if len(self.chain) > 0:
            return self.chain[-1].timestamp
        return self.chain.time()


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
    if not initializer:
        return eth_utils.to_bytes(hexstr="0x")
    else:
        return initializer.encode_input(*args)


class BrownieETHCall(ETHCall):
    def _handle_exception(self, err):
        if isinstance(err, VirtualMachineError) and err.revert_type == "revert":
            raise RevertError(err.revert_msg)
        super()._handle_exception(err)

    @classmethod
    def get_eth_function(cls, wrapper, eth_method, eth_variant=None):
        if eth_variant:
            return getattr(wrapper.contract, eth_method)[eth_variant]
        else:
            return getattr(wrapper.contract, eth_method)

    @classmethod
    def get_eth_function_and_mutability(cls, wrapper, eth_method, eth_variant=None):
        function = cls.get_eth_function(wrapper, eth_method, eth_variant)
        return function, function.abi["stateMutability"]

    @classmethod
    def parse(cls, wrapper, value_type, value):
        if value_type.startswith("(") and value_type.endswith(")"):
            # It's a tuple / struct
            value_types = [t.strip() for t in value_type.strip("()").split(",")]
            return tuple(
                cls.parse(wrapper, vt, value[i]) for i, vt in enumerate(value_types)
            )
        if value_type == "address":
            if isinstance(value, (LocalAccount, Account)):
                return value
            elif isinstance(value, (Contract, ProjectContract)):
                return value.address
            elif isinstance(value, ETHWrapper):
                return value.contract.address
            elif isinstance(value, str) and value.startswith("0x"):
                return value
            return wrapper.provider.address_book.get_account(value)
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


class BrownieProvider(BaseProvider):
    eth_call = BrownieETHCall

    def __init__(self, time_control=None, address_book=None):
        self.time_control = time_control or BrownieTimeControl()
        self.address_book = address_book or BrownieAddressBook(accounts)

    def get_contract_factory(self, eth_contract):
        ret = getattr(brownie, eth_contract, None)
        if ret is not None:
            return ret
        # Might be a manually loaded project or an interface
        project = brownie.project.get_loaded_projects()[0]
        ret = getattr(project, eth_contract, None)
        if ret is not None:
            return ret
        return getattr(project.interface, eth_contract)

    def get_events(self, eth_wrapper, event_name, filter_kwargs={}):
        """Returns a list of events given a filter, like this:

        >>> provider.get_events(currencywrapper, "Transfer", dict(fromBlock=0))
        [AttributeDict({
            'args': AttributeDict(
                {'from': '0x0000000000000000000000000000000000000000',
                 'to': '0x56Cd397bAA08F2339F0ae470DEA99D944Ac064bB',
                 'value': 6000000000000000000000}),
            'event': 'Transfer',
            'logIndex': 0,
            'transactionIndex': 0,
            'transactionHash': HexBytes(
                '0x406b2cf8de2f12f4d0958e9f0568dc0919f337ed399f8d8d78ddbc648c01f806'
                ),
            'address': '0xf8BedC7458fb8cAbD616B5e90F57c34c392e7168',
            'blockHash': HexBytes('0x7b23c6ea49759bcee769b1a357dec7f63f03bdb1dd13f1ee19868925954134b3'),
            'blockNumber': 23
        })]
        """
        w3 = brownie.network.web3
        w3_contract = w3.eth.contract(abi=eth_wrapper.contract.abi, address=eth_wrapper.contract.address)
        event = getattr(w3_contract.events, event_name)
        if "fromBlock" not in filter_kwargs:
            filter_kwargs["fromBlock"] = self.get_first_block(eth_wrapper)
        event_filter = event.createFilter(**filter_kwargs)
        return event_filter.get_all_entries()

    def deploy(self, eth_contract, init_params, from_, **kwargs):
        factory = self.get_contract_factory(eth_contract)
        kwargs["from"] = from_
        return factory.deploy(*init_params, kwargs)

    def init_eth_wrapper(self, eth_wrapper, owner, init_params, kwargs):
        eth_wrapper.owner = self.address_book.get_account(owner)
        for library in eth_wrapper.libraries_required:
            self.get_contract_factory(library).deploy({"from": eth_wrapper.owner})
        eth_contract = self.get_contract_factory(eth_wrapper.eth_contract)
        if eth_wrapper.proxy_kind is None:
            eth_wrapper.contract = eth_contract.deploy(*init_params, {"from": eth_wrapper.owner})
        elif eth_wrapper.proxy_kind == "uups" and not SKIP_PROXY:
            constructor_params, init_params = init_params
            real_contract = eth_contract.deploy(*constructor_params, {"from": eth_wrapper.owner})
            proxy_contract = self.get_contract_factory("ERC1967Proxy").deploy(
                real_contract,
                encode_function_data(getattr(real_contract, "initialize", None), *init_params),
                {"from": eth_wrapper.owner}
            )
            eth_wrapper.contract = Contract.from_abi(eth_wrapper.eth_contract, proxy_contract.address,
                                                     eth_contract.abi)
        elif eth_wrapper.proxy_kind == "uups" and SKIP_PROXY:
            constructor_params, init_params = init_params
            eth_wrapper.contract = eth_contract.deploy(*constructor_params, {"from": eth_wrapper.owner})
            eth_wrapper.contract.initialize(*init_params, {"from": eth_wrapper.owner})

    def build_contract(self, contract_address, contract_factory, contract_name=None):
        return Contract.from_abi(contract_name or "Contract", contract_address, contract_factory.abi)
