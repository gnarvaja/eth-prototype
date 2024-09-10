import random
from enum import Enum
from warnings import warn

from environs import Env
from eth_abi import encode
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import add_0x_prefix
from hexbytes import HexBytes
from web3 import Web3
from web3.constants import ADDRESS_ZERO

from .contracts import RevertError

env = Env()

AA_BUNDLER_SENDER = env.str("AA_BUNDLER_SENDER", None)
AA_BUNDLER_ENTRYPOINT = env.str("AA_BUNDLER_ENTRYPOINT", "0x0000000071727De22E5E9d8BAf0edAc6f37da032")
AA_BUNDLER_EXECUTOR_PK = env.str("AA_BUNDLER_EXECUTOR_PK", None)
AA_BUNDLER_PROVIDER = env.str("AA_BUNDLER_PROVIDER", "alchemy")
AA_BUNDLER_GAS_LIMIT_FACTOR = env.float("AA_BUNDLER_GAS_LIMIT_FACTOR", 1)
AA_BUNDLER_PRIORITY_GAS_PRICE_FACTOR = env.float("AA_BUNDLER_PRIORITY_GAS_PRICE_FACTOR", 1)
AA_BUNDLER_BASE_GAS_PRICE_FACTOR = env.float("AA_BUNDLER_BASE_GAS_PRICE_FACTOR", 1)

NonceMode = Enum(
    "NonceMode",
    [
        "RANDOM_KEY",  # first time initializes a random key and increments nonce locally with calling the blockchain
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

NONCE_CACHE = {}
RANDOM_NONCE_KEY = None


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


def pack_user_operation(user_operation):
    # https://github.com/eth-infinitism/account-abstraction/blob/develop/contracts/interfaces/PackedUserOperation.sol
    return {
        "sender": user_operation["sender"],
        "nonce": _to_uint(user_operation["nonce"]),
        "initCode": "0x",
        "callData": user_operation["callData"],
        "accountGasLimits": pack_two(user_operation["verificationGasLimit"], user_operation["callGasLimit"]),
        "preVerificationGas": _to_uint(user_operation["preVerificationGas"]),
        "gasFees": pack_two(user_operation["maxPriorityFeePerGas"], user_operation["maxFeePerGas"]),
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
    )


def hash_packed_user_operation(packed_user_op, chain_id, entry_point):
    return Web3.keccak(
        hexstr=encode(
            ["bytes32", "address", "uint256"],
            [hash_packed_user_operation_only(packed_user_op), entry_point, chain_id],
        ).hex()
    )


def sign_user_operation(private_key, user_operation, chain_id, entry_point):
    packed_user_op = pack_user_operation(user_operation)
    hash = hash_packed_user_operation(packed_user_op, chain_id, entry_point)
    signature = Account.sign_message(encode_defunct(hexstr=hash.hex()), private_key)
    return signature.signature


def make_nonce(nonce_key, nonce):
    nonce_key = _to_uint(nonce_key)
    nonce = _to_uint(nonce)
    return (nonce_key << 64) | nonce


def fetch_nonce(w3, account, entry_point, nonce_key):
    ep = w3.eth.contract(abi=GET_NONCE_ABI, address=entry_point)
    return ep.functions.getNonce(account, nonce_key).call()


def get_random_nonce_key():
    global RANDOM_NONCE_KEY
    if RANDOM_NONCE_KEY is None:
        RANDOM_NONCE_KEY = random.randint(1, 2**192 - 1)
    return RANDOM_NONCE_KEY


def get_nonce_and_key(w3, tx, nonce_mode, entry_point=AA_BUNDLER_ENTRYPOINT, fetch=False):
    nonce_key = tx.get("nonceKey", None)
    nonce = tx.get("nonce", None)

    if nonce_key is None:
        if nonce_mode == NonceMode.RANDOM_KEY:
            nonce_key = get_random_nonce_key()
        else:
            nonce_key = AA_BUNDLER_NONCE_KEY

    if nonce is None:
        if fetch or nonce_mode == NonceMode.FIXED_KEY_FETCH_ALWAYS:
            nonce = fetch_nonce(w3, get_sender(tx), entry_point, nonce_key)
        elif nonce_key not in NONCE_CACHE:
            nonce = 0
        else:
            nonce = NONCE_CACHE[nonce_key]
    return nonce_key, nonce


def handle_response_error(resp, w3, tx, retry_nonce):
    if "AA25" in resp["error"]["message"] and AA_BUNDLER_MAX_GETNONCE_RETRIES > 0:
        # Retry fetching the nonce
        if retry_nonce == AA_BUNDLER_MAX_GETNONCE_RETRIES:
            raise RevertError(resp["error"]["message"])
        warn(f'{resp["error"]["message"]} error, I will retry fetching the nonce')
        return send_transaction(w3, tx, retry_nonce=(retry_nonce or 0) + 1)
    else:
        raise RevertError(resp["error"]["message"])


def get_base_fee(w3):
    blk = w3.eth.get_block("latest")
    return int(_to_uint(blk["baseFeePerGas"]) * AA_BUNDLER_BASE_GAS_PRICE_FACTOR)


def get_sender(tx):
    if "from" not in tx or tx["from"] == ADDRESS_ZERO:
        if AA_BUNDLER_SENDER is None:
            raise RuntimeError("Must define AA_BUNDLER_SENDER or send 'from' in the TX")
        return AA_BUNDLER_SENDER
    else:
        return tx["from"]


def send_transaction(w3, tx, retry_nonce=None):
    nonce_key, nonce = get_nonce_and_key(
        w3, tx, AA_BUNDLER_NONCE_MODE, entry_point=AA_BUNDLER_ENTRYPOINT, fetch=retry_nonce is not None
    )
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
        "sender": get_sender(tx),
        "nonce": hex(make_nonce(nonce_key, nonce)),
        "callData": call_data,
        "signature": dummy_signature,
    }

    if AA_BUNDLER_PROVIDER == "alchemy":
        resp = w3.provider.make_request(
            "eth_estimateUserOperationGas", [user_operation, AA_BUNDLER_ENTRYPOINT]
        )
        if "error" in resp:
            return handle_response_error(resp, w3, tx, retry_nonce)

        user_operation.update(resp["result"])

        resp = w3.provider.make_request("rundler_maxPriorityFeePerGas", [])
        if "error" in resp:
            raise RevertError(resp["error"]["message"])
        max_priority_fee_per_gas = int(_to_uint(resp["result"]) * AA_BUNDLER_PRIORITY_GAS_PRICE_FACTOR)
        user_operation["maxPriorityFeePerGas"] = hex(max_priority_fee_per_gas)
        user_operation["maxFeePerGas"] = hex(max_priority_fee_per_gas + get_base_fee(w3))
        user_operation["callGasLimit"] = hex(
            int(_to_uint(user_operation["callGasLimit"]) * AA_BUNDLER_GAS_LIMIT_FACTOR)
        )
    elif AA_BUNDLER_PROVIDER == "gelato":
        user_operation.update(
            {
                "preVerificationGas": "0x00",
                "callGasLimit": "0x00",
                "verificationGasLimit": "0x00",
                "maxFeePerGas": "0x00",
                "maxPriorityFeePerGas": "0x00",
            }
        )
    user_operation["signature"] = add_0x_prefix(
        sign_user_operation(
            AA_BUNDLER_EXECUTOR_PK, user_operation, tx["chainId"], AA_BUNDLER_ENTRYPOINT
        ).hex()
    )
    # Remove paymaster related fields
    user_operation.pop("paymaster", None)
    user_operation.pop("paymasterData", None)
    user_operation.pop("paymasterVerificationGasLimit", None)
    user_operation.pop("paymasterPostOpGasLimit", None)

    resp = w3.provider.make_request("eth_sendUserOperation", [user_operation, AA_BUNDLER_ENTRYPOINT])
    if "error" in resp:
        return handle_response_error(resp, w3, tx, retry_nonce)

    # Store nonce in the cache, so next time uses a new nonce
    NONCE_CACHE[nonce_key] = nonce + 1
    return {"userOpHash": resp["result"]}
