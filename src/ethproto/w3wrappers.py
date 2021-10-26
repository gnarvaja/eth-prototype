import os
import json
from .contracts import RevertError
from .wrappers import ETHCall, AddressBook, MAXUINT256, ETHWrapper, SKIP_PROXY
from environs import Env
from eth_account.account import Account, LocalAccount

env = Env()

CONTRACT_JSON_PATH = env.list("CONTRACT_JSON_PATH", [], delimiter=":")


class W3TimeControl:
    def __init__(self, w3):
        self.w3 = w3

    def fast_forward(self, secs):
        self.w3.provider.make_request("evm_increaseTime", [secs])
        # Not tested!

    @property
    def now(self):
        return self.w3.get_block("latest").timestamp


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
                self.name_to_address[name] = self.w3.eth.account.create().address
        return self.name_to_address[name]

    def get_name(self, account_or_address):
        if isinstance(account_or_address, (LocalAccount, )):
            account_or_address = account_or_address.address

        for name, addr in self.name_to_address.items():
            if addr == account_or_address:
                return name
        return None


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
                return wrapper.provider.w3.eth.wait_for_transaction_receipt(tx_hash)

        return eth_function

    def _handle_exception(self, err):
        if str(err).startswith("execution reverted: "):
            raise RevertError(str(err)[len("execution reverted: "):])
        super()._handle_exception(err)

    @classmethod
    def parse(cls, wrapper, value_type, value):
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


class W3Provider:
    eth_call = W3ETHCall

    def __init__(self, w3, address_book=None, contracts_path=None):
        self.w3 = w3
        self.contracts_path = contracts_path or CONTRACT_JSON_PATH
        self.contract_def_cache = {}
        self.address_book = address_book or W3AddressBook(w3)
        self.time_control = W3TimeControl(w3)

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

    def init_eth_wrapper(self, eth_wrapper, owner, init_params, kwargs):
        eth_wrapper.owner = self.address_book.get_account(owner)
        assert not eth_wrapper.libraries_required, "Not supported"

        eth_contract = self.get_contract_factory(eth_wrapper.eth_contract)
        if eth_wrapper.proxy_kind is None:
            eth_wrapper.contract = self.construct(eth_contract, init_params, {"from": eth_wrapper.owner})
        elif eth_wrapper.proxy_kind == "uups" and not SKIP_PROXY:
            real_contract = self.construct(eth_contract, (), {"from": eth_wrapper.owner})
            ERC1967Proxy = self.get_contract_factory("ERC1967Proxy")
            init_data = real_contract.functions.initialize(*init_params).buildTransaction()["data"]
            proxy_contract = self.construct(
                ERC1967Proxy,
                (real_contract.address, init_data),
                {"from": eth_wrapper.owner}
            )
            eth_wrapper.contract = self.w3.eth.contract(abi=eth_contract.abi, address=proxy_contract.address)
        elif eth_wrapper.proxy_kind == "uups" and SKIP_PROXY:
            eth_wrapper.contract = self.construct(eth_contract, (), {"from": eth_wrapper.owner})
            # TODO
            eth_wrapper.contract.functions.initialize(*init_params, {"from": eth_wrapper.owner})

    def construct(self, contract_factory, constructor_args=(), transact_kwargs={}):
        tx_hash = contract_factory.constructor(*constructor_args).transact(transact_kwargs)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        # TODO: verify receipt OK
        return self.w3.eth.contract(abi=contract_factory.abi, address=receipt.contractAddress)

    def build_contract(self, contract_address, contract_factory, contract_name=None):
        return self.w3.eth.contract(abi=contract_factory.abi, address=contract_address)
