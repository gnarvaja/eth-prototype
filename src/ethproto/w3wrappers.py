import os
import json
from .contracts import RevertError
from .wrappers import (
    ETHCall, AddressBook, MAXUINT256, ETHWrapper, SKIP_PROXY, register_provider, BaseProvider
)
from environs import Env
from eth_account.account import Account, LocalAccount
from eth_account.signers.base import BaseAccount
from web3.exceptions import ExtraDataLengthError
from web3.middleware import geth_poa_middleware
from eth_event import get_topic_map, decode_logs

env = Env()

CONTRACT_JSON_PATH = env.list("CONTRACT_JSON_PATH", [], delimiter=":")
W3_TRANSACT_MODE = env.str("W3_TRANSACT_MODE", "transact")
W3_ADDRESS_BOOK_PREFIX = env.str("W3_ADDRESS_BOOK_PREFIX", "W3_ADDR_")
W3_ADDRESS_BOOK_CREATE_UNKNOWN = env.str("W3_ADDRESS_BOOK_CREATE_UNKNOWN", "")


class W3TimeControl:
    def __init__(self, w3):
        self.w3 = w3

    def fast_forward(self, secs):
        self.w3.provider.make_request("evm_increaseTime", [secs])
        # Not tested!

    @property
    def now(self):
        return self.w3.get_block("latest").timestamp


def register_w3_provider(provider_key="w3", tester=None, provider_kwargs={}):
    if tester is None:
        try:
            import eth_tester  # noqa
        except ImportError:
            tester = False

    if tester:
        from web3 import Web3
        w3 = Web3(Web3.EthereumTesterProvider())
    else:
        from web3.auto import w3
    assert w3.isConnected()
    try:
        w3.eth.get_block("latest")
    except ExtraDataLengthError:
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)

    # If address_book not provided and there are envs with W3_ADDRESS_BOOK_PREFIX,
    # use W3EnvAddressBook
    if "address_book" not in provider_kwargs and not tester:
        if [k for k in os.environ.keys() if k.startswith(W3_ADDRESS_BOOK_PREFIX)]:
            provider_kwargs["address_book"] = W3EnvAddressBook(
                w3, create_unknown_name=W3_ADDRESS_BOOK_CREATE_UNKNOWN
            )

    provider = W3Provider(w3, **provider_kwargs)
    register_provider(provider_key, provider)
    return provider


def transact(provider, function, tx_kwargs):
    if W3_TRANSACT_MODE == "transact":
        # uses eth_sendTransaction
        tx_hash = function.transact({**provider.tx_kwargs, **tx_kwargs})
    elif W3_TRANSACT_MODE == "sign-and-send":
        tx_kwargs = {**provider.tx_kwargs, **tx_kwargs}
        from_ = tx_kwargs.pop("from")
        if isinstance(from_, BaseAccount):
            tx_kwargs["from"] = from_.address
        else:  # it's a string, I try to get the PK from the environment
            from_ = provider.address_book.get_signer_account(from_)
            tx_kwargs["from"] = from_.address
        tx = function.buildTransaction(
            {**tx_kwargs, **{"nonce": provider.w3.eth.get_transaction_count(from_.address)}}
        )
        signed_tx = from_.sign_transaction(tx)
        tx_hash = provider.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    return provider.w3.eth.wait_for_transaction_receipt(tx_hash)


class W3AddressBook(AddressBook):
    def __init__(self, w3, eth_accounts=None):
        self.w3 = w3
        self._eth_accounts = eth_accounts
        self.name_to_address = {}
        self.last_account_used = -1

    @property
    def eth_accounts(self):
        if self._eth_accounts is None:
            self._eth_accounts = self.w3.eth.accounts
        return self._eth_accounts

    def get_account(self, name):
        if isinstance(name, (Account, LocalAccount)):
            return name
        if name is None:
            return self.ZERO
        if type(name) == str and name.startswith("0x"):
            return name
        if name not in self.name_to_address:
            self.last_account_used += 1
            try:
                self.name_to_address[name] = self.eth_accounts[self.last_account_used]
            except IndexError:
                self.name_to_address[name] = self.w3.eth.account.create().address
        return self.name_to_address[name]

    def get_name(self, account_or_address):
        if isinstance(account_or_address, (LocalAccount, )):
            account_or_address = account_or_address.address

        for name, addr in self.name_to_address.items():
            if addr == account_or_address:
                return name
        return None


class W3EnvAddressBook(AddressBook):
    def __init__(self, w3, env_prefix=W3_ADDRESS_BOOK_PREFIX, create_unknown_name=False):
        """Creates an address book read from environment variables

        @param create_unknown_name "addr-only" means if name not found, creates an address but doesn't store
                                   the PK (can't sign)
                                   "yes" or True means if name not found, local address is created
                                   "no" or False doesn't create addresses for unknown names
        """
        self.w3 = w3
        self.signers = {}
        self.name_to_address = {}
        self.create_unknown_name = create_unknown_name

        for k, value in os.environ.items():
            if not k.startswith(env_prefix):
                continue
            if k.endswith("_ADDR"):
                continue  # Addresses linked to names
            addr = k[len(env_prefix):]
            if addr.startswith("0x"):
                account = w3.account.from_key(value)
                assert account.address == addr
            else:  # It's a name
                name = addr
                account = Account.from_key(value)
                if f"{env_prefix}{name}_ADDR" in os.environ:
                    address = os.environ[f"{env_prefix}{name}_ADDR"]
                    assert account.address == address
                self.name_to_address[name] = account.address
            self.signers[account.address] = account

    def get_account(self, name):
        if isinstance(name, (Account, LocalAccount)):
            return name
        if name is None:
            return self.ZERO
        if type(name) == str and name.startswith("0x"):
            return name
        if name in self.name_to_address:
            return self.name_to_address[name]

        if self.create_unknown_name:
            account = self.w3.eth.account.create()
            self.name_to_address[name] = account.address
            if self.create_unknown_name != "addr-only":
                self.signers[account.address] = account
            return account.address
        raise RuntimeError(f"No account found for name {name}")

    def get_name(self, account_or_address):
        if isinstance(account_or_address, (LocalAccount, )):
            account_or_address = account_or_address.address

        for name, addr in self.name_to_address.items():
            if addr == account_or_address:
                return name
        return None

    def get_signer_account(self, address):
        return self.signers[address]


class ReceiptWrapper:
    """Class that makes w3 receipts more user friendly"""

    def __init__(self, receipt, contract):
        self._receipt = receipt
        self._contract = contract

    @property
    def events(self):
        if not hasattr(self, "_events"):
            topic_map = get_topic_map(self._contract.abi)
            logs = decode_logs(self._receipt.logs, topic_map, allow_undecoded=True)
            evts = {}
            for evt in logs:
                evt_name = evt["name"]
                evt_params = dict((d["name"], d["value"]) for d in evt["data"])
                if evt_name not in evts:
                    evts[evt_name] = evt_params
                elif type(evts[evt_name]) == dict:
                    evts[evt_name] = [evts[evt_name], evt_params]  # start a list
                else:  # it's already a list
                    evts[evt_name].append(evt_params)
            self._events = evts
        return self._events

    def __getattr__(self, attr_name):
        return getattr(self._receipt, attr_name)


class W3ETHCall(ETHCall):
    @classmethod
    def find_function_abi(cls, contract, eth_method, eth_variant):
        abis = [x for x in contract.abi if "name" in x and x["name"] == eth_method]
        if len(abis) == 1:
            return abis[0]
        # TODO: eth_variant
        raise RuntimeError(f"Method {eth_method} not found")

    @classmethod
    def get_eth_function_and_mutability(cls, wrapper, eth_method, eth_variant=None):
        function = getattr(wrapper.contract.functions, eth_method)  # TODO: eth_variant
        function_abi = cls.find_function_abi(wrapper.contract, eth_method, eth_variant)
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
                return transact(wrapper.provider, function(*args), (transact_args or {}))

        return eth_function, function_abi["stateMutability"]

    def normalize_receipt(self, wrapper, receipt):
        return ReceiptWrapper(receipt, wrapper.contract)

    def _handle_exception(self, err):
        if str(err).startswith("execution reverted: "):
            raise RevertError(str(err)[len("execution reverted: "):])
        super()._handle_exception(err)

    @classmethod
    def parse(cls, wrapper, value_type, value):
        if value_type.startswith("(") and value_type.endswith(")"):
            # It's a tuple / struct
            value_types = [t.strip() for t in value_type.split(",")]
            return tuple(
                cls.parse(wrapper, vt, value[i]) for i, vt in enumerate(value_types)
            )
        if value_type == "address":
            if isinstance(value, (LocalAccount, Account)):
                return value
#            elif isinstance(value, (Contract, ProjectContract)):
#                return value.address
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


class W3Provider(BaseProvider):
    eth_call = W3ETHCall

    def __init__(self, w3, address_book=None, contracts_path=None, tx_kwargs=None):
        self.w3 = w3
        self.contracts_path = contracts_path or CONTRACT_JSON_PATH
        self.contract_def_cache = {}
        self.address_book = address_book or W3AddressBook(w3)
        self.time_control = W3TimeControl(w3)
        self.tx_kwargs = tx_kwargs or {}

    def get_contract_def(self, eth_contract):
        if eth_contract not in self.contract_def_cache:
            json_file = None
            for contract_path in self.contracts_path:
                for sub_path, _, files in os.walk(contract_path):
                    if f"{eth_contract}.json" in files:
                        json_file = os.path.join(sub_path, f"{eth_contract}.json")
                        break
                if json_file is not None:
                    break
            else:
                raise RuntimeError(f"{eth_contract} JSON definition not found in {self.contracts_path}")
            self.contract_def_cache[eth_contract] = json.load(open(json_file))
        return self.contract_def_cache[eth_contract]

    def get_contract_factory(self, eth_contract):
        contract_def = self.get_contract_def(eth_contract)
        return self.w3.eth.contract(abi=contract_def["abi"], bytecode=contract_def.get("bytecode", None))

    def deploy(self, eth_contract, init_params, from_, **kwargs):
        factory = self.get_contract_factory(eth_contract)
        kwargs["from"] = from_
        return self.construct(factory, init_params, kwargs)

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
        contract = eth_wrapper.contract
        event = getattr(contract.events, event_name)
        if "fromBlock" not in filter_kwargs:
            filter_kwargs["fromBlock"] = self.get_first_block(eth_wrapper)
        event_filter = event.createFilter(**filter_kwargs)
        return event_filter.get_all_entries()

    def init_eth_wrapper(self, eth_wrapper, owner, init_params, kwargs):
        eth_wrapper.owner = self.address_book.get_account(owner)
        assert not eth_wrapper.libraries_required, "Not supported"

        eth_contract = self.get_contract_factory(eth_wrapper.eth_contract)
        if eth_wrapper.proxy_kind is None:
            eth_wrapper.contract = self.construct(eth_contract, init_params, {"from": eth_wrapper.owner})
        elif eth_wrapper.proxy_kind == "uups" and not SKIP_PROXY:
            constructor_params, init_params = init_params
            real_contract = self.construct(eth_contract, constructor_params, {"from": eth_wrapper.owner})
            ERC1967Proxy = self.get_contract_factory("ERC1967Proxy")
            init_data = real_contract.functions.initialize(
                *init_params
            ).buildTransaction({**self.tx_kwargs, **{"from": eth_wrapper.owner}})["data"]
            proxy_contract = self.construct(
                ERC1967Proxy,
                (real_contract.address, init_data),
                {**self.tx_kwargs, **{"from": eth_wrapper.owner}}
            )
            eth_wrapper.contract = self.w3.eth.contract(
                abi=eth_contract.abi,
                address=proxy_contract.address
            )
        elif eth_wrapper.proxy_kind == "uups" and SKIP_PROXY:
            constructor_params, init_params = init_params
            eth_wrapper.contract = self.construct(eth_contract, constructor_params,
                                                  {"from": eth_wrapper.owner})
            transact(
                self,
                eth_wrapper.contract.functions.initialize(*init_params),
                {"from": eth_wrapper.owner}
            )

    def construct(self, contract_factory, constructor_args=(), transact_kwargs={}):
        receipt = transact(
            self,
            contract_factory.constructor(*constructor_args),
            transact_kwargs
        )
        return self.w3.eth.contract(abi=contract_factory.abi, address=receipt.contractAddress)

    def build_contract(self, contract_address, contract_factory, contract_name=None):
        return self.w3.eth.contract(abi=contract_factory.abi, address=contract_address)
