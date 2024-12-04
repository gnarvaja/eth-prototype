import random
from collections import defaultdict
from dataclasses import dataclass, replace
from enum import Enum
from threading import local
from warnings import warn

from environs import Env
from eth_abi import encode
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_typing import HexAddress
from eth_utils import add_0x_prefix, function_signature_to_4byte_selector
from hexbytes import HexBytes
from web3 import Web3
from web3.constants import ADDRESS_ZERO
from web3.types import TxParams

from .contracts import RevertError

env = Env()

AA_BUNDLER_URL = env.str("AA_BUNDLER_URL", env.str("WEB3_PROVIDER_URI", "http://localhost:8545"))
AA_BUNDLER_SENDER = env.str("AA_BUNDLER_SENDER", None)
AA_BUNDLER_ENTRYPOINT = env.str("AA_BUNDLER_ENTRYPOINT", "0x0000000071727De22E5E9d8BAf0edAc6f37da032")
AA_BUNDLER_EXECUTOR_PK = env.str("AA_BUNDLER_EXECUTOR_PK", None)
AA_BUNDLER_PROVIDER = env.str("AA_BUNDLER_PROVIDER", "alchemy")
AA_BUNDLER_GAS_LIMIT_FACTOR = env.float("AA_BUNDLER_GAS_LIMIT_FACTOR", 1)
AA_BUNDLER_PRIORITY_GAS_PRICE_FACTOR = env.float("AA_BUNDLER_PRIORITY_GAS_PRICE_FACTOR", 1)
AA_BUNDLER_BASE_GAS_PRICE_FACTOR = env.float("AA_BUNDLER_BASE_GAS_PRICE_FACTOR", 1)
AA_BUNDLER_VERIFICATION_GAS_FACTOR = env.float("AA_BUNDLER_VERIFICATION_GAS_FACTOR", 1)

NonceMode = Enum(
    "NonceMode",
    [
        "RANDOM_KEY",  # first time initializes a random key and increments nonce locally with calling the blockchain
        "RANDOM_KEY_EVERYTIME",  # initializes a random key every time and increments nonce locally
        "FIXED_KEY_LOCAL_NONCE",  # uses a fixed key, keeps nonce locally and fetches the nonce when receiving
        # 'AA25 invalid account nonce'
        "FIXED_KEY_FETCH_ALWAYS",  # uses a fixed key, always fetches unless received as parameter
    ],
)

AA_BUNDLER_NONCE_MODE = env.enum("AA_BUNDLER_NONCE_MODE", default="FIXED_KEY_LOCAL_NONCE", type=NonceMode)
AA_BUNDLER_NONCE_KEY = env.int("AA_BUNDLER_NONCE_KEY", 0)
AA_BUNDLER_MAX_GETNONCE_RETRIES = env.int("AA_BUNDLER_MAX_GETNONCE_RETRIES", 3)


GET_NONCE_ABI = [
    {
        "inputs": [
            {"internalType": "address", "name": "sender", "type": "address"},
            {"internalType": "uint192", "name": "key", "type": "uint192"},
        ],
        "name": "getNonce",
        "outputs": [{"internalType": "uint256", "name": "nonce", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    }
]

NONCE_CACHE = defaultdict(lambda: 0)
RANDOM_NONCE_KEY = local()

DUMMY_SIGNATURE = HexBytes(
    "0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c"
)


@dataclass(frozen=True)
class UserOpEstimation:
    """eth_estimateUserOperationGas response"""

    pre_verification_gas: int
    verification_gas_limit: int
    call_gas_limit: int
    paymaster_verification_gas_limit: int


@dataclass(frozen=True)
class GasPrice:
    max_priority_fee_per_gas: int
    max_fee_per_gas: int


@dataclass(frozen=True)
class Tx:
    target: HexAddress
    data: HexBytes
    value: int

    nonce_key: HexBytes = None
    nonce: int = None
    from_: HexAddress = ADDRESS_ZERO
    chain_id: int = None

    @classmethod
    def from_tx_params(cls, params: TxParams) -> "Tx":
        return cls(
            target=params["to"],
            data=HexBytes(params["data"]),
            value=params["value"],
            from_=params.get("from", ADDRESS_ZERO),
            chain_id=params.get("chainId", None),
        )

    def as_execute_args(self):
        return [self.target, self.value, self.data]


@dataclass(frozen=True)
class UserOperation:
    EXECUTE_ARG_TYPES = ["address", "uint256", "bytes"]
    EXECUTE_SELECTOR = function_signature_to_4byte_selector(f"execute({','.join(EXECUTE_ARG_TYPES)})")

    sender: HexBytes
    nonce: int
    call_data: HexBytes

    max_fee_per_gas: int = 0
    max_priority_fee_per_gas: int = 0

    call_gas_limit: int = 0
    verification_gas_limit: int = 0
    pre_verification_gas: int = 0

    signature: HexBytes = DUMMY_SIGNATURE

    init_code: HexBytes = HexBytes("0x")
    paymaster_and_data: HexBytes = HexBytes("0x")

    @classmethod
    def from_tx(cls, tx: Tx, nonce):
        return cls(
            sender=get_sender(tx),
            nonce=nonce,
            call_data=add_0x_prefix(
                (cls.EXECUTE_SELECTOR + encode(cls.EXECUTE_ARG_TYPES, tx.as_execute_args())).hex()
            ),
        )

    def as_reduced_dict(self):
        return {
            "sender": self.sender,
            "nonce": "0x%x" % self.nonce,
            "callData": self.call_data,
            "signature": add_0x_prefix(self.signature.hex()),
        }

    def as_dict(self):
        return {
            "sender": self.sender,
            "nonce": "0x%x" % self.nonce,
            "callData": self.call_data,
            "callGasLimit": "0x%x" % self.call_gas_limit,
            "verificationGasLimit": "0x%x" % self.verification_gas_limit,
            "preVerificationGas": "0x%x" % self.pre_verification_gas,
            "maxPriorityFeePerGas": "0x%x" % self.max_priority_fee_per_gas,
            "maxFeePerGas": "0x%x" % self.max_fee_per_gas,
            "signature": add_0x_prefix(self.signature.hex()),
        }

    def add_estimation(self, estimation: UserOpEstimation) -> "UserOperation":
        return replace(
            self,
            call_gas_limit=estimation.call_gas_limit,
            verification_gas_limit=estimation.verification_gas_limit,
            pre_verification_gas=estimation.pre_verification_gas,
        )

    def add_gas_price(self, gas_price: GasPrice) -> "UserOperation":
        return replace(
            self,
            max_priority_fee_per_gas=gas_price.max_priority_fee_per_gas,
            max_fee_per_gas=gas_price.max_fee_per_gas,
        )

    def sign(self, private_key: HexBytes, chain_id, entrypoint) -> "UserOperation":
        signature = Account.sign_message(
            encode_defunct(
                hexstr=PackedUserOperation.from_user_operation(self)
                .hash_full(chain_id=chain_id, entrypoint=entrypoint)
                .hex()
            ),
            private_key,
        )
        return replace(self, signature=signature.signature)


@dataclass(frozen=True)
class PackedUserOperation:
    sender: HexBytes
    nonce: int
    call_data: HexBytes

    account_gas_limits: HexBytes
    pre_verification_gas: int
    gas_fees: HexBytes

    init_code: HexBytes = HexBytes("0x")
    paymaster_and_data: HexBytes = HexBytes("0x")
    signature: HexBytes = HexBytes("0x")

    @classmethod
    def from_user_operation(cls, user_operation: UserOperation):
        return cls(
            sender=user_operation.sender,
            nonce=user_operation.nonce,
            call_data=user_operation.call_data,
            account_gas_limits=pack_two(user_operation.verification_gas_limit, user_operation.call_gas_limit),
            pre_verification_gas=user_operation.pre_verification_gas,
            gas_fees=pack_two(user_operation.max_priority_fee_per_gas, user_operation.max_fee_per_gas),
            init_code=user_operation.init_code,
            paymaster_and_data=user_operation.paymaster_and_data,
            signature=user_operation.signature,
        )

    def hash(self):
        # https://github.com/eth-infinitism/account-abstraction/blob/develop/contracts/core/UserOperationLib.sol#L54
        hash_init_code = Web3.solidity_keccak(["bytes"], [self.init_code])
        hash_call_data = Web3.solidity_keccak(["bytes"], [self.call_data])
        hash_paymaster_and_data = Web3.solidity_keccak(["bytes"], [self.paymaster_and_data])
        return Web3.keccak(
            hexstr=encode(
                ["address", "uint256", "bytes32", "bytes32", "bytes32", "uint256", "bytes32", "bytes32"],
                [
                    self.sender,
                    self.nonce,
                    hash_init_code,
                    hash_call_data,
                    HexBytes(self.account_gas_limits),
                    self.pre_verification_gas,
                    HexBytes(self.gas_fees),
                    hash_paymaster_and_data,
                ],
            ).hex()
        )

    def hash_full(self, chain_id, entrypoint):
        return Web3.keccak(
            hexstr=encode(
                ["bytes32", "address", "uint256"],
                [self.hash(), entrypoint, chain_id],
            ).hex()
        )


def pack_two(a, b):
    a = HexBytes(a).hex()
    b = HexBytes(b).hex()
    return "0x" + a.zfill(32) + b.zfill(32)


def _to_uint(x):
    if isinstance(x, str):
        return int(x, 16)
    elif isinstance(x, int):
        return x
    raise RuntimeError(f"Invalid int value {x}")


def make_nonce(nonce_key, nonce):
    nonce_key = _to_uint(nonce_key)
    nonce = _to_uint(nonce)
    return (nonce_key << 64) | nonce


def fetch_nonce(w3, account, entrypoint, nonce_key):
    ep = w3.eth.contract(abi=GET_NONCE_ABI, address=entrypoint)
    return ep.functions.getNonce(account, nonce_key).call()


def get_random_nonce_key(force=False):
    if force or getattr(RANDOM_NONCE_KEY, "key", None) is None:
        RANDOM_NONCE_KEY.key = random.randint(1, 2**192 - 1)
    return RANDOM_NONCE_KEY.key


def consume_nonce(nonce_key, nonce):
    NONCE_CACHE[nonce_key] = max(NONCE_CACHE[nonce_key], nonce + 1)


def check_nonce_error(resp, retry_nonce):
    """Returns the next nonce if resp contains a nonce error and retries weren't exhausted
    Raises RevertError otherwise
    """
    if "AA25" in resp["error"]["message"] and AA_BUNDLER_MAX_GETNONCE_RETRIES > 0:
        # Retry fetching the nonce
        if retry_nonce == AA_BUNDLER_MAX_GETNONCE_RETRIES:
            raise RevertError(resp["error"]["message"])
        warn(f'{resp["error"]["message"]} error, I will retry fetching the nonce')
        return (retry_nonce or 0) + 1
    else:
        raise RevertError(resp["error"]["message"])


def get_sender(tx):
    if tx.from_ == ADDRESS_ZERO:
        if AA_BUNDLER_SENDER is None:
            raise RuntimeError("Must define AA_BUNDLER_SENDER or send 'from' in the TX")
        return AA_BUNDLER_SENDER
    else:
        return tx.from_


class Bundler:
    def __init__(
        self,
        w3: Web3,
        bundler_url: str = AA_BUNDLER_URL,
        bundler_type: str = AA_BUNDLER_PROVIDER,
        entrypoint: HexAddress = AA_BUNDLER_ENTRYPOINT,
        nonce_mode: NonceMode = AA_BUNDLER_NONCE_MODE,
        fixed_nonce_key: int = AA_BUNDLER_NONCE_KEY,
        verification_gas_factor: float = AA_BUNDLER_VERIFICATION_GAS_FACTOR,
        gas_limit_factor: float = AA_BUNDLER_GAS_LIMIT_FACTOR,
        priority_gas_price_factor: float = AA_BUNDLER_PRIORITY_GAS_PRICE_FACTOR,
        base_gas_price_factor: float = AA_BUNDLER_BASE_GAS_PRICE_FACTOR,
        executor_pk: HexBytes = AA_BUNDLER_EXECUTOR_PK,
    ):
        self.w3 = w3
        self.bundler = Web3(Web3.HTTPProvider(bundler_url), middleware=[])
        self.bundler_type = bundler_type
        self.entrypoint = entrypoint
        self.nonce_mode = nonce_mode
        self.fixed_nonce_key = fixed_nonce_key
        self.verification_gas_factor = verification_gas_factor
        self.gas_limit_factor = gas_limit_factor
        self.priority_gas_price_factor = priority_gas_price_factor
        self.base_gas_price_factor = base_gas_price_factor
        self.executor_pk = executor_pk

    def __str__(self):
        return (
            f"Bundler(type={self.bundler_type}, entrypoint={self.entrypoint}, nonce_mode={self.nonce_mode}"
            f"fixed_nonce_key={self.fixed_nonce_key}, verification_gas_factor={self.verification_gas_factor},"
            f"gas_limit_factor={self.gas_limit_factor}, priority_gas_price_factor={self.priority_gas_price_factor},"
            f"base_gas_price_factor={self.base_gas_price_factor})"
        )

    def get_nonce_and_key(self, tx: Tx, fetch=False):
        nonce_key = tx.nonce_key
        nonce = tx.nonce

        if nonce_key is None:
            if self.nonce_mode == NonceMode.RANDOM_KEY:
                nonce_key = get_random_nonce_key()
            elif self.nonce_mode == NonceMode.RANDOM_KEY_EVERYTIME:
                nonce_key = get_random_nonce_key(force=True)
            else:
                nonce_key = self.fixed_nonce_key

        if nonce is None:
            if fetch or self.nonce_mode == NonceMode.FIXED_KEY_FETCH_ALWAYS:
                nonce = fetch_nonce(self.w3, get_sender(tx), self.entrypoint, nonce_key)
            else:
                nonce = NONCE_CACHE[nonce_key]
        return nonce_key, nonce

    def get_base_fee(self):
        blk = self.w3.eth.get_block("latest")
        return int(_to_uint(blk["baseFeePerGas"]) * self.base_gas_price_factor)

    def estimate_user_operation_gas(self, user_operation: UserOperation) -> UserOpEstimation:
        resp = self.bundler.provider.make_request(
            "eth_estimateUserOperationGas", [user_operation.as_reduced_dict(), self.entrypoint]
        )
        if "error" in resp:
            raise RevertError(resp["error"]["message"])

        paymaster_verification_gas_limit = resp["result"].get("paymasterVerificationGasLimit", "0x00")
        return UserOpEstimation(
            pre_verification_gas=int(resp["result"].get("preVerificationGas", "0x00"), 16),
            verification_gas_limit=int(
                int(resp["result"].get("verificationGasLimit", "0x00"), 16) * self.verification_gas_factor
            ),
            call_gas_limit=int(int(resp["result"].get("callGasLimit", "0x00"), 16) * self.gas_limit_factor),
            paymaster_verification_gas_limit=(
                int(paymaster_verification_gas_limit, 16)
                if paymaster_verification_gas_limit is not None
                else 0
            ),
        )

    def alchemy_gas_price(self):
        resp = self.bundler.provider.make_request("rundler_maxPriorityFeePerGas", [])
        if "error" in resp:
            raise RevertError(resp["error"]["message"])
        max_priority_fee_per_gas = int(int(resp["result"], 16) * self.priority_gas_price_factor)
        max_fee_per_gas = max_priority_fee_per_gas + self.get_base_fee()

        return GasPrice(max_priority_fee_per_gas=max_priority_fee_per_gas, max_fee_per_gas=max_fee_per_gas)

    def build_user_operation(self, tx: Tx, retry_nonce=None) -> UserOperation:
        nonce_key, nonce = self.get_nonce_and_key(tx, fetch=retry_nonce is not None)
        # Consume the nonce, even if the userop may fail later
        consume_nonce(nonce_key, nonce)

        user_operation = UserOperation.from_tx(tx, make_nonce(nonce_key, nonce))
        estimation = self.estimate_user_operation_gas(user_operation)

        user_operation = user_operation.add_estimation(estimation)

        if self.bundler_type == "alchemy":
            gas_price = self.alchemy_gas_price()
            user_operation = user_operation.add_gas_price(gas_price)

        elif self.bundler_type == "generic":
            # At the moment generic just prices the gas at 0
            pass

        else:
            warn(f"Unknown bundler_type: {self.bundler_type}")

        return user_operation

    def send_transaction(self, tx: Tx, retry_nonce=None):
        user_operation = self.build_user_operation(tx, retry_nonce).sign(
            self.executor_pk, tx.chain_id, self.entrypoint
        )

        resp = self.bundler.provider.make_request(
            "eth_sendUserOperation", [user_operation.as_dict(), self.entrypoint]
        )
        if "error" in resp:
            next_nonce = check_nonce_error(resp, retry_nonce)
            return self.send_transaction(tx, retry_nonce=next_nonce)

        return {"userOpHash": resp["result"]}
