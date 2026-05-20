"""Account Abstraction types and dataclasses."""

from dataclasses import dataclass, replace

from eth_abi import encode
from eth_abi.packed import encode_packed
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_typing import HexAddress
from eth_utils import add_0x_prefix, function_signature_to_4byte_selector
from hexbytes import HexBytes
from web3 import Web3
from web3.constants import ADDRESS_ZERO
from web3.types import TxParams

from .contracts import RevertError

# ============================================================================
# EXCEPTIONS
# ============================================================================


class BundlerRevertError(RevertError):
    """Bundler specific revert error"""

    def __init__(self, message, userop=None, response=None):
        super().__init__(message)
        self.message = message
        self.userop = userop
        self.response = response


class BundlerError(Exception):
    pass


class NonceError(BundlerRevertError):
    """Raised when the bundler returns an AA25 invalid account nonce error."""

    pass


# ============================================================================
# CONSTANTS
# ============================================================================

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

DUMMY_SIGNATURE = HexBytes(
    "0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c"
)


# ============================================================================
# DATACLASSES
# ============================================================================


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
class PaymasterAndData:
    paymaster: HexAddress
    paymaster_data: HexBytes
    paymaster_verification_gas_limit: int
    paymaster_post_op_gas_limit: int


@dataclass(frozen=True)
class AlchemyGasAndPaymasterAndData:
    estimation: UserOpEstimation
    gas_price: GasPrice
    paymaster_and_data: PaymasterAndData


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

    EXECUTE_USEROP_ARG_TYPES = ["address", "address", "uint256", "bytes"]
    EXECUTE_USEROP_SELECTOR = function_signature_to_4byte_selector(
        #               PackedUserOperation struct
        "executeUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes),bytes32)"
    )

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

    paymaster: HexAddress = None
    paymaster_data: HexBytes = HexBytes("0x")
    paymaster_verification_gas_limit: int = 0
    paymaster_post_op_gas_limit: int = 0

    @classmethod
    def from_tx(cls, tx: Tx, nonce, execute_user_op_context=None):
        # Late import to avoid circular dependency
        from .aa_bundler import get_sender

        if execute_user_op_context is not None:
            call_data = add_0x_prefix(
                (
                    cls.EXECUTE_USEROP_SELECTOR
                    + encode(
                        cls.EXECUTE_USEROP_ARG_TYPES, [execute_user_op_context, tx.target, tx.value, tx.data]
                    )
                ).hex()
            )
        else:
            call_data = add_0x_prefix(
                (cls.EXECUTE_SELECTOR + encode(cls.EXECUTE_ARG_TYPES, tx.as_execute_args())).hex()
            )
        return cls(
            sender=get_sender(tx),
            nonce=nonce,
            call_data=call_data,
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
            "initCode": add_0x_prefix(self.init_code.hex()),
            "callData": self.call_data,
            "callGasLimit": "0x%x" % self.call_gas_limit,
            "verificationGasLimit": "0x%x" % self.verification_gas_limit,
            "preVerificationGas": "0x%x" % self.pre_verification_gas,
            "maxPriorityFeePerGas": "0x%x" % self.max_priority_fee_per_gas,
            "maxFeePerGas": "0x%x" % self.max_fee_per_gas,
            "signature": add_0x_prefix(self.signature.hex()),
            "paymaster": self.paymaster,
            "paymasterData": self.paymaster_data.to_0x_hex(),
            "paymasterVerificationGasLimit": "0x%x" % self.paymaster_verification_gas_limit,
            "paymasterPostOpGasLimit": "0x%x" % self.paymaster_post_op_gas_limit,
        }

    @classmethod
    def from_dict(cls, d):
        return cls(
            sender=HexBytes(d["sender"]),
            nonce=int(d["nonce"], 16),
            init_code=HexBytes(d["initCode"]),
            call_data=HexBytes(d["callData"]),
            call_gas_limit=int(d["callGasLimit"], 16),
            verification_gas_limit=int(d["verificationGasLimit"], 16),
            pre_verification_gas=int(d["preVerificationGas"], 16),
            max_fee_per_gas=int(d["maxFeePerGas"], 16),
            max_priority_fee_per_gas=int(d["maxPriorityFeePerGas"], 16),
            signature=HexBytes(d["signature"]),
            paymaster=d["paymaster"],
            paymaster_data=HexBytes(d["paymasterData"]),
            paymaster_verification_gas_limit=int(d["paymasterVerificationGasLimit"], 16),
            paymaster_post_op_gas_limit=int(d["paymasterPostOpGasLimit"], 16),
        )

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

    def add_paymaster_and_data(self, paymaster_and_data: PaymasterAndData) -> "UserOperation":
        return replace(
            self,
            paymaster=paymaster_and_data.paymaster,
            paymaster_data=paymaster_and_data.paymaster_data,
            paymaster_verification_gas_limit=paymaster_and_data.paymaster_verification_gas_limit,
            paymaster_post_op_gas_limit=paymaster_and_data.paymaster_post_op_gas_limit,
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

    def as_dict(self):
        return {
            "sender": HexBytes(self.sender),
            "nonce": "0x%x" % self.nonce,
            "initCode": add_0x_prefix(HexBytes(self.init_code).hex()),
            "callData": HexBytes(self.call_data),
            "accountGasLimits": add_0x_prefix(HexBytes(self.account_gas_limits).hex()),
            "preVerificationGas": "0x%x" % self.pre_verification_gas,
            "gasFees": add_0x_prefix(HexBytes(self.gas_fees).hex()),
            "paymasterAndData": add_0x_prefix(HexBytes(self.paymaster_and_data).hex()),
            "signature": add_0x_prefix(HexBytes(self.signature).hex()),
        }

    @classmethod
    def from_dict(cls, d):
        return cls(
            sender=HexBytes(d["sender"]),
            nonce=int(d["nonce"], 16),
            init_code=HexBytes(d["initCode"]),
            call_data=HexBytes(d["callData"]),
            account_gas_limits=HexBytes(d["accountGasLimits"]),
            pre_verification_gas=int(d["preVerificationGas"], 16),
            gas_fees=HexBytes(d["gasFees"]),
            paymaster_and_data=HexBytes(d["paymasterAndData"]),
            signature=HexBytes(d["signature"]),
        )

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
            paymaster_and_data=(
                HexBytes(
                    encode_packed(
                        ["address", "uint128", "uint128", "bytes"],
                        [
                            user_operation.paymaster,
                            user_operation.paymaster_verification_gas_limit,
                            user_operation.paymaster_post_op_gas_limit,
                            user_operation.paymaster_data,
                        ],
                    )
                )
                if user_operation.paymaster is not None
                else HexBytes("0x")
            ).to_0x_hex(),
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


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================


def pack_two(a, b):
    a = HexBytes(a).hex()
    b = HexBytes(b).hex()
    return "0x" + a.zfill(32) + b.zfill(32)
