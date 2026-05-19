import random
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import replace
from enum import Enum
from threading import local
from typing import ClassVar, Optional

from environs import Env
from eth_account import Account
from eth_typing import ChecksumAddress, HexAddress
from hexbytes import HexBytes
from requests import HTTPError
from web3 import Web3
from web3.constants import ADDRESS_ZERO
from web3.types import StateOverride

from .aa_types import PackedUserOperation  # noqa: F401
from .aa_types import pack_two  # noqa: F401
from .aa_types import (  # Import everything for backwards compatibility; Exceptions; Constants; Dataclasses; Functions
    DUMMY_SIGNATURE,
    GET_NONCE_ABI,
    AlchemyGasAndPaymasterAndData,
    BundlerError,
    BundlerRevertError,
    GasPrice,
    NonceError,
    PaymasterAndData,
    Tx,
    UserOperation,
    UserOpEstimation,
)

env = Env()

AA_BUNDLER_URL = env.str("AA_BUNDLER_URL", env.str("WEB3_PROVIDER_URI", None))
AA_BUNDLER_SENDER = env.str("AA_BUNDLER_SENDER", None)
AA_BUNDLER_ENTRYPOINT = env.str("AA_BUNDLER_ENTRYPOINT", "0x0000000071727De22E5E9d8BAf0edAc6f37da032")
AA_BUNDLER_EXECUTOR_PK = env.str("AA_BUNDLER_EXECUTOR_PK", None)
AA_BUNDLER_PROVIDER = env.str("AA_BUNDLER_PROVIDER", "generic")
AA_BUNDLER_GAS_LIMIT_FACTOR = env.float("AA_BUNDLER_GAS_LIMIT_FACTOR", 1)
AA_BUNDLER_PRIORITY_GAS_PRICE_FACTOR = env.float("AA_BUNDLER_PRIORITY_GAS_PRICE_FACTOR", 1)
AA_BUNDLER_BASE_GAS_PRICE_FACTOR = env.float("AA_BUNDLER_BASE_GAS_PRICE_FACTOR", 1)
AA_BUNDLER_VERIFICATION_GAS_FACTOR = env.float("AA_BUNDLER_VERIFICATION_GAS_FACTOR", 1)
AA_BUNDLER_MAX_FEE_PER_GAS = env.int("AA_BUNDLER_MAX_FEE_PER_GAS", 200000000000)  # 200 gwei

AA_BUNDLER_STATE_OVERRIDES = env.json("AA_BUNDLER_STATE_OVERRIDES", default={})

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

AA_BUNDLER_NONCE_MODE = env.enum("AA_BUNDLER_NONCE_MODE", default="FIXED_KEY_LOCAL_NONCE", enum=NonceMode)
AA_BUNDLER_NONCE_KEY = env.int("AA_BUNDLER_NONCE_KEY", 0)
AA_BUNDLER_ALCHEMY_GAS_POLICY_ID = env.str("AA_BUNDLER_ALCHEMY_GAS_POLICY_ID", None)
AA_BUNDLER_USE_EXECUTE_USER_OP = env.bool("AA_BUNDLER_USE_EXECUTE_USER_OP", False)

NONCE_CACHE = defaultdict(lambda: 0)
RANDOM_NONCE_KEY = local()


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


def is_nonce_error(resp):
    """Check if a bundler response contains an AA25 nonce error."""
    return "error" in resp and "AA25" in resp["error"]["message"]


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
        max_fee_per_gas: int = AA_BUNDLER_MAX_FEE_PER_GAS,
        executor_pk: HexBytes = AA_BUNDLER_EXECUTOR_PK,
        overrides: StateOverride = AA_BUNDLER_STATE_OVERRIDES,
        use_execute_user_op: bool = AA_BUNDLER_USE_EXECUTE_USER_OP,
    ):
        self.w3 = w3
        self.bundler_w3 = Web3(Web3.HTTPProvider(bundler_url), middleware=[]) if bundler_url else w3
        self.bundler_type = bundler_type
        self.entrypoint = entrypoint
        self.nonce_mode = nonce_mode
        self.fixed_nonce_key = fixed_nonce_key
        self.verification_gas_factor = verification_gas_factor
        self.gas_limit_factor = gas_limit_factor
        self.priority_gas_price_factor = priority_gas_price_factor
        self.base_gas_price_factor = base_gas_price_factor
        self.account = Account.from_key(executor_pk) if executor_pk else None
        self.max_fee_per_gas = max_fee_per_gas

        # stateOverrideSet mapping to use when calling eth_estimateUserOperationGas
        # https://docs.alchemy.com/reference/eth-estimateuseroperationgas
        self.overrides = overrides
        self.use_execute_user_op = use_execute_user_op

        strategy_class = GasEstimationStrategy._strategies.get(bundler_type)
        if strategy_class is None:
            raise BundlerError(f"Unknown bundler_type: {bundler_type}")
        self.gas_strategy = strategy_class(self)

    def __str__(self):
        return (
            f"Bundler(type={self.bundler_type}, entrypoint={self.entrypoint}, nonce_mode={self.nonce_mode}, "
            f"fixed_nonce_key={self.fixed_nonce_key}, verification_gas_factor={self.verification_gas_factor}, "
            f"gas_limit_factor={self.gas_limit_factor}, priority_gas_price_factor={self.priority_gas_price_factor}, "
            f"base_gas_price_factor={self.base_gas_price_factor}, max_fee_per_gas={self.max_fee_per_gas}), "
            f"use_execute_user_op={self.use_execute_user_op}, signer={self.account.address if self.account else None}"
        )

    @property
    def execute_user_op_context(self) -> ChecksumAddress:
        if self.use_execute_user_op and self.account:
            return self.account.address
        return None

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

    def build_user_operation(self, tx: Tx, enable_cap=True) -> UserOperation:
        nonce_key, nonce = self.get_nonce_and_key(tx)
        consume_nonce(nonce_key, nonce)

        user_operation = UserOperation.from_tx(
            tx, make_nonce(nonce_key, nonce), execute_user_op_context=self.execute_user_op_context
        )

        estimation = self.gas_strategy.estimate_gas_limits(user_operation)
        user_operation = user_operation.add_estimation(estimation)

        gas_price = self.gas_strategy.estimate_gas_price(user_operation)
        if enable_cap:
            gas_price = replace(
                gas_price,
                max_fee_per_gas=min(gas_price.max_fee_per_gas, self.max_fee_per_gas),
            )
        user_operation = user_operation.add_gas_price(gas_price)

        paymaster_and_data = self.gas_strategy.estimate_paymaster(user_operation)
        if paymaster_and_data is not None:
            user_operation = user_operation.add_paymaster_and_data(paymaster_and_data)

        return user_operation

    def send_transaction(self, tx: Tx):
        user_operation = self.build_user_operation(tx).sign(self.account.key, tx.chain_id, self.entrypoint)
        return self.send_user_operation(user_operation)

    def send_user_operation(self, user_operation: UserOperation):
        resp = self.bundler_w3.provider.make_request(
            "eth_sendUserOperation", [user_operation.as_dict(), self.entrypoint]
        )
        if "error" in resp:
            if is_nonce_error(resp):
                raise NonceError(resp["error"]["message"], userop=user_operation, response=resp)
            raise BundlerRevertError(resp["error"]["message"], userop=user_operation, response=resp)
        return {"userOpHash": resp["result"]}

    def get_user_operation(self, user_op_hash):
        resp = self.bundler_w3.provider.make_request("eth_getUserOperationByHash", [user_op_hash])
        if "error" in resp:
            raise BundlerRevertError(resp["error"]["message"], response=resp)
        return resp["result"]


class GasEstimationStrategy(ABC):
    _strategies: ClassVar[dict] = {}

    @classmethod
    def register(cls, name: str):
        def decorator(strategy_cls):
            cls._strategies[name] = strategy_cls
            return strategy_cls

        return decorator

    def __init__(self, bundler: "Bundler", **kwargs):
        self.bundler = bundler

    def _estimate_user_operation_gas(self, user_operation: UserOperation) -> UserOpEstimation:
        resp = self.bundler.bundler_w3.provider.make_request(
            "eth_estimateUserOperationGas",
            [user_operation.as_dict(), self.bundler.entrypoint, self.bundler.overrides],
        )
        if "error" in resp:
            raise BundlerRevertError(resp["error"]["message"], user_operation, resp)

        paymaster_verification_gas_limit = resp["result"].get("paymasterVerificationGasLimit", "0x00")
        return UserOpEstimation(
            pre_verification_gas=int(resp["result"].get("preVerificationGas", "0x00"), 16),
            verification_gas_limit=int(
                int(resp["result"].get("verificationGasLimit", "0x00"), 16)
                * self.bundler.verification_gas_factor
            ),
            call_gas_limit=int(
                int(resp["result"].get("callGasLimit", "0x00"), 16) * self.bundler.gas_limit_factor
            ),
            paymaster_verification_gas_limit=(
                int(paymaster_verification_gas_limit, 16)
                if paymaster_verification_gas_limit is not None
                else 0
            ),
        )

    def _get_base_fee(self) -> int:
        blk = self.bundler.w3.eth.get_block("latest")
        return int(_to_uint(blk["baseFeePerGas"]) * self.bundler.base_gas_price_factor)

    @abstractmethod
    def estimate_gas_limits(self, user_operation: UserOperation) -> UserOpEstimation:
        ...

    @abstractmethod
    def estimate_gas_price(self, user_operation: UserOperation) -> GasPrice:
        ...

    def estimate_paymaster(self, user_operation: UserOperation) -> Optional[PaymasterAndData]:
        return None


@GasEstimationStrategy.register("generic")
class GenericGasStrategy(GasEstimationStrategy):
    def estimate_gas_limits(self, user_operation: UserOperation) -> UserOpEstimation:
        return self._estimate_user_operation_gas(user_operation)

    def estimate_gas_price(self, user_operation: UserOperation) -> GasPrice:
        base_fee = self._get_base_fee()
        priority_fee = self.bundler.w3.eth.max_priority_fee
        max_priority_fee_per_gas = int(priority_fee * self.bundler.priority_gas_price_factor)
        max_fee_per_gas = max_priority_fee_per_gas + base_fee
        return GasPrice(max_priority_fee_per_gas=max_priority_fee_per_gas, max_fee_per_gas=max_fee_per_gas)


@GasEstimationStrategy.register("pimlico")
class PimlicoGasStrategy(GasEstimationStrategy):
    def estimate_gas_limits(self, user_operation: UserOperation) -> UserOpEstimation:
        return self._estimate_user_operation_gas(user_operation)

    def estimate_gas_price(self, user_operation: UserOperation) -> GasPrice:
        resp = self.bundler.bundler_w3.provider.make_request("pimlico_getUserOperationGasPrice", [])
        if "error" in resp:
            raise BundlerRevertError(resp["error"]["message"], response=resp)
        # {
        #   "jsonrpc": "2.0",
        #   "id": 1,
        #   "result": {
        #           "slow": {
        #           "maxFeePerGas": "0x829b42b5",
        #           "maxPriorityFeePerGas": "0x829b42b5"
        #       },
        #           "standard": {
        #           "maxFeePerGas": "0x88d36a75",
        #           "maxPriorityFeePerGas": "0x88d36a75"
        #       },
        #           "fast": {
        #           "maxFeePerGas": "0x8f0b9234",
        #           "maxPriorityFeePerGas": "0x8f0b9234"
        #       }
        #   }
        # }
        priority_fee = int(resp["result"]["standard"]["maxPriorityFeePerGas"], 16)
        total_fee = int(resp["result"]["standard"]["maxFeePerGas"], 16)
        base_fee = total_fee - priority_fee
        max_priority_fee_per_gas = int(priority_fee * self.bundler.priority_gas_price_factor)
        max_fee_per_gas = max_priority_fee_per_gas + base_fee
        return GasPrice(max_priority_fee_per_gas=max_priority_fee_per_gas, max_fee_per_gas=max_fee_per_gas)


@GasEstimationStrategy.register("alchemy")
class AlchemyGasStrategy(GasEstimationStrategy):
    def __init__(self, bundler: "Bundler", **kwargs):
        super().__init__(bundler)
        gas_policy_id = kwargs.pop("gas_policy_id", AA_BUNDLER_ALCHEMY_GAS_POLICY_ID)
        if gas_policy_id is None:
            raise BundlerError("Must provide alchemy_gas_policy_id when using alchemy bundler_type")
        self._gas_policy_id = gas_policy_id
        self._cached_result: Optional[AlchemyGasAndPaymasterAndData] = None

    def _get_estimation(self, user_operation: UserOperation) -> AlchemyGasAndPaymasterAndData:
        if self._cached_result is None:
            self._cached_result = self._alchemy_estimation(user_operation)
        return self._cached_result

    def _alchemy_estimation(self, user_operation: UserOperation) -> AlchemyGasAndPaymasterAndData:
        try:
            resp = self.bundler.bundler_w3.provider.make_request(
                "alchemy_requestGasAndPaymasterAndData",
                [
                    {
                        "policyId": self._gas_policy_id,
                        "entryPoint": self.bundler.entrypoint,
                        "dummySignature": DUMMY_SIGNATURE,
                        "userOperation": user_operation.as_reduced_dict(),
                        "overrides": {
                            "maxFeePerGas": {"multiplier": self.bundler.base_gas_price_factor},
                            "maxPriorityFeePerGas": {"multiplier": self.bundler.priority_gas_price_factor},
                            "callGasLimit": {"multiplier": self.bundler.gas_limit_factor},
                            "verificationGasLimit": {"multiplier": self.bundler.verification_gas_factor},
                        },
                        # Alchemy seems to be ignoring this, even though it's documented
                        "stateOverrideSet": self.bundler.overrides,
                    }
                ],
            )
        except HTTPError as e:
            raise BundlerRevertError(
                f"HTTP error while requesting gas and paymaster data: {str(e)}",
                userop=user_operation,
                response=e.response.text,
            ) from e

        if "error" in resp:
            raise BundlerRevertError(resp["error"]["message"], userop=user_operation, response=resp)

        # {
        #     "callGasLimit": "0x3dab",
        #     "paymasterVerificationGasLimit": "0x9afa",
        #     "paymasterPostOpGasLimit": "0x0",
        #     "verificationGasLimit": "0xac33",
        #     "maxPriorityFeePerGas": "0x7aef40a00",
        #     "paymaster": "0x2cc0c7981D846b9F2a16276556f6e8cb52BfB633",
        #     "maxFeePerGas": "0xaf9fe62e48",
        #     "paymasterData": "0xabcd...",
        #     "preVerificationGas": "0xb8ec"
        #   }

        estimation = UserOpEstimation(
            pre_verification_gas=int(resp["result"]["preVerificationGas"], 16),
            verification_gas_limit=int(resp["result"]["verificationGasLimit"], 16),
            call_gas_limit=int(resp["result"]["callGasLimit"], 16),
            paymaster_verification_gas_limit=int(resp["result"]["paymasterVerificationGasLimit"], 16),
        )
        gas_price = GasPrice(
            max_priority_fee_per_gas=int(resp["result"]["maxPriorityFeePerGas"], 16),
            max_fee_per_gas=int(resp["result"]["maxFeePerGas"], 16),
        )
        paymaster_and_data = PaymasterAndData(
            paymaster=resp["result"]["paymaster"],
            paymaster_data=HexBytes(resp["result"]["paymasterData"]),
            paymaster_verification_gas_limit=int(resp["result"]["paymasterVerificationGasLimit"], 16),
            paymaster_post_op_gas_limit=int(resp["result"]["paymasterPostOpGasLimit"], 16),
        )
        return AlchemyGasAndPaymasterAndData(
            estimation=estimation,
            gas_price=gas_price,
            paymaster_and_data=paymaster_and_data,
        )

    def estimate_gas_limits(self, user_operation: UserOperation) -> UserOpEstimation:
        return self._get_estimation(user_operation).estimation

    def estimate_gas_price(self, user_operation: UserOperation) -> GasPrice:
        return self._get_estimation(user_operation).gas_price

    def estimate_paymaster(self, user_operation: UserOperation) -> PaymasterAndData:
        return self._get_estimation(user_operation).paymaster_and_data


@GasEstimationStrategy.register("zeroprice")
class ZeroPriceGasStrategy(GasEstimationStrategy):
    def estimate_gas_limits(self, user_operation: UserOperation) -> UserOpEstimation:
        return self._estimate_user_operation_gas(user_operation)

    def estimate_gas_price(self, user_operation: UserOperation) -> GasPrice:
        return GasPrice(max_priority_fee_per_gas=0, max_fee_per_gas=0)
