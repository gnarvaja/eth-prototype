import requests
from environs import Env
from eth_abi import encode
from eth_account import Account
from eth_account.messages import encode_defunct
from hexbytes import HexBytes
from web3 import Web3
from .contracts import RevertError

env = Env()

AA_BUNDLER_SENDER = env.str("AA_BUNDLER_SENDER", None)
AA_BUNDLER_ENTRYPOINT = env.str("AA_BUNDLER_ENTRYPOINT", "0x0000000071727De22E5E9d8BAf0edAc6f37da032")
AA_BUNDLER_EXECUTOR_PK = env.str("AA_BUNDLER_EXECUTOR_PK", None)


def pack_two(a, b):
    a = HexBytes(a).hex()[2:]
    b = HexBytes(b).hex()[2:]
    return "0x" + a.zfill(32) + b.zfill(32)


def _to_uint(x):
    if isinstance(x, str):
        return int(x, 16)
    elif isinstance(x, int):
        return x
    raise RuntimeError(f"Invalid int value {x}")


def pack_user_operation(user_operation):
    # https://github.com/eth-infinitism/account-abstraction/blob/develop/contracts/interfaces/PackedUserOperation.sol
    return {
        "sender": user_operation["sender"],
        "nonce": _to_uint(user_operation["nonce"]),
        "initCode": "0x",
        "callData": user_operation["callData"],
        "accountGasLimits": pack_two(user_operation["verificationGasLimit"], user_operation["callGasLimit"]),
        "preVerificationGas": _to_uint(user_operation["preVerificationGas"]),
        "gasFees": pack_two(user_operation["maxFeePerGas"], user_operation["maxPriorityFeePerGas"]),
        "paymasterAndData": "0x",
        "signature": "0x",
    }


def hash_packed_user_operation_only(packed_user_op):
    # https://github.com/eth-infinitism/account-abstraction/blob/develop/contracts/core/UserOperationLib.sol#L54
    hash_init_code = Web3.solidity_keccak(["bytes"], [packed_user_op["initCode"]])
    hash_call_data = Web3.solidity_keccak(["bytes"], [packed_user_op["callData"]])
    hash_paymaster_and_data = Web3.solidity_keccak(["bytes"], [packed_user_op["paymasterAndData"]])
    return Web3.keccak(
        hexstr=encode(
            ["address", "uint256", "bytes32", "bytes32", "bytes32", "uint256", "bytes32", "bytes32"],
            [
                packed_user_op["sender"],
                packed_user_op["nonce"],
                hash_init_code,
                hash_call_data,
                HexBytes(packed_user_op["accountGasLimits"]),
                packed_user_op["preVerificationGas"],
                HexBytes(packed_user_op["gasFees"]),
                hash_paymaster_and_data,
            ],
        ).hex()
    ).hex()


def hash_packed_user_operation(packed_user_op, chain_id, entry_point):
    return Web3.keccak(
        hexstr=encode(
            ["bytes32", "address", "uint256"],
            [HexBytes(hash_packed_user_operation_only(packed_user_op)), entry_point, chain_id],
        ).hex()
    ).hex()


def sign_user_operation(private_key, user_operation, chain_id, entry_point):
    packed_user_op = pack_user_operation(user_operation)
    hash = hash_packed_user_operation(packed_user_op, chain_id, entry_point)
    signature = Account.sign_message(encode_defunct(hexstr=hash), private_key)
    return signature.signature.hex()


def send_transaction(w3, tx):
    nonce = 0
    # "0xb61d27f6" = bytes4 hash of execute(address,uint256,bytes)
    call_data = (
        "0xb61d27f6"
        + encode(["address", "uint256", "bytes"], [tx["to"], tx["value"], HexBytes(tx["data"])]).hex()
    )
    dummy_signature = (
        "0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c"
    )
    user_operation = {
        "sender": tx.get("from", AA_BUNDLER_SENDER),
        "nonce": hex(nonce),
        "callData": call_data,
        "signature": dummy_signature,
    }
    resp = w3.provider.make_request("eth_estimateUserOperationGas", [user_operation, AA_BUNDLER_ENTRYPOINT])
    if "error" in resp:
        raise RevertError(resp["error"]["message"])
    user_operation.update(resp["result"])

    resp = w3.provider.make_request("rundler_maxPriorityFeePerGas", [])
    if "error" in resp:
        raise RevertError(resp["error"]["message"])
    max_priority_fee_per_gas = resp["result"]

    user_operation["maxFeePerGas"] = max_priority_fee_per_gas
    user_operation["maxPriorityFeePerGas"] = max_priority_fee_per_gas
    user_operation["signature"] = sign_user_operation(
        AA_BUNDLER_EXECUTOR_PK, user_operation, tx["chainId"], AA_BUNDLER_ENTRYPOINT
    )
    # Remove paymaster related fields
    user_operation.pop("paymaster", None)
    user_operation.pop("paymasterData", None)
    user_operation.pop("paymasterVerificationGasLimit", None)
    user_operation.pop("paymasterPostOpGasLimit", None)

    resp = w3.provider.make_request("eth_sendUserOperation", [user_operation, AA_BUNDLER_ENTRYPOINT])
    if "error" in resp:
        raise RevertError(resp["error"]["message"])

    return resp["result"]
