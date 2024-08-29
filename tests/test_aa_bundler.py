from hexbytes import HexBytes
from ethproto import aa_bundler
from web3.constants import HASH_ZERO
from unittest.mock import MagicMock


def test_pack_two():
    assert aa_bundler.pack_two(0, 0) == HASH_ZERO
    assert aa_bundler.pack_two(1, 2) == "0x0000000000000000000000000000000100000000000000000000000000000002"
    assert (
        aa_bundler.pack_two("0x1", "0x2")
        == "0x0000000000000000000000000000000100000000000000000000000000000002"
    )
    assert aa_bundler.pack_two(HexBytes(2), HexBytes(3) == "0x{:032x}{:032x}".format(2, 3))


TEST_CALL_DATA = "0x47e1da2a000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000000020000000000000000000000002791bca1f2de4661ed88a30c99a7a9449aa841740000000000000000000000002791bca1f2de4661ed88a30c99a7a9449aa8417400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000044a9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c800000000000000000000000000000000000000000000000000000000004c4b40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb0000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc000000000000000000000000000000000000000000000000000000000098968000000000000000000000000000000000000000000000000000000000"  # noqa

# Private key of index=1 of seed phrase ["test"] * 11 + ["junk"]
TEST_PRIVATE_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
CHAIN_ID = 31337
ENTRYPOINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"


user_operation = {
    "sender": "0x515f3Db6c4249919B74eA55915969944fEA4B311",
    "nonce": 0,
    "initCode": "0x",
    "callData": TEST_CALL_DATA,
    "callGasLimit": 999999,
    "verificationGasLimit": 999999,
    "preVerificationGas": 999999,
    "maxFeePerGas": 1000000000,
    "maxPriorityFeePerGas": 1000000000,
    "paymaster": "0x0000000000000000000000000000000000000000",
    "paymasterData": "0x",
    "paymasterVerificationGasLimit": 0,
    "paymasterPostOpGasLimit": 0,
}


def test_pack_user_operation():
    expected = {
        "sender": "0x515f3Db6c4249919B74eA55915969944fEA4B311",
        "nonce": 0,
        "initCode": "0x",
        "callData": TEST_CALL_DATA,
        "accountGasLimits": "0x000000000000000000000000000f423f000000000000000000000000000f423f",
        "preVerificationGas": 999999,
        "gasFees": "0x0000000000000000000000003b9aca000000000000000000000000003b9aca00",
        "paymasterAndData": "0x",
        "signature": "0x",
    }
    assert aa_bundler.pack_user_operation(user_operation) == expected


def test_hash_packed_user_operation():
    packed = aa_bundler.pack_user_operation(user_operation)
    hash = aa_bundler.hash_packed_user_operation_only(packed)
    assert hash == "0xb3c6cda6d25de5a793bc280200673119f76f92017c97dacd26bc1329771b96a4"
    hash = aa_bundler.hash_packed_user_operation(packed, CHAIN_ID, ENTRYPOINT)
    assert hash == "0x213b6b5f785983fa3310d6ae06e63ff883915ad5454dd422e15d9778a9e1da48"


def test_sign_user_operation():
    signature = aa_bundler.sign_user_operation(TEST_PRIVATE_KEY, user_operation, CHAIN_ID, ENTRYPOINT)
    assert (
        signature
        == "0x9a2e58cbe1d7c79b933c115e6d041fca080c5a1f572b78116c36b956faf9bf660b4fc10f339fd608d11b56072407bb29d311edb3a79f312f6f8375a97692870d1b"  # noqa
    )


def test_send_transaction():
    w3 = MagicMock()
    w3.eth.chain_id = CHAIN_ID

    aa_bundler.AA_BUNDLER_EXECUTOR_PK = TEST_PRIVATE_KEY

    tx = {
        "value": 0,
        "chainId": 137,
        "from": "0xE8B412158c205B0F605e0FC09dCdA27d3F140FE9",
        "to": "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
        "data": "0x095ea7b30000000000000000000000007ace242f32208d836a2245df957c08547059bf45ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  # noqa
    }

    def make_request(method, params):
        if method == "eth_estimateUserOperationGas":
            assert len(params) == 2
            assert params[1] == ENTRYPOINT
            assert params[0] == {
                "sender": "0xE8B412158c205B0F605e0FC09dCdA27d3F140FE9",
                "nonce": "0x0",
                "callData": "0xb61d27f60000000000000000000000002791bca1f2de4661ed88a30c99a7a9449aa84174000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044095ea7b30000000000000000000000007ace242f32208d836a2245df957c08547059bf45ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000",
                "signature": "0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c",
            }
            return {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "preVerificationGas": "0xb430",
                    "callGasLimit": "0xcbb8",
                    "verificationGasLimit": "0x13664",
                    "paymasterVerificationGasLimit": None,
                },
            }
        elif method == "rundler_maxPriorityFeePerGas":
            assert len(params) == 0
            return {"jsonrpc": "2.0", "id": 1, "result": "0x7ffffffff"}
        elif method == "eth_sendUserOperation":
            assert len(params) == 2
            assert params[1] == ENTRYPOINT
            assert params[0] == {
                "sender": "0xE8B412158c205B0F605e0FC09dCdA27d3F140FE9",
                "nonce": "0x0",
                "callData": "0xb61d27f60000000000000000000000002791bca1f2de4661ed88a30c99a7a9449aa84174000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044095ea7b30000000000000000000000007ace242f32208d836a2245df957c08547059bf45ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000",
                "callGasLimit": "0xcbb8",
                "verificationGasLimit": "0x13664",
                "preVerificationGas": "0xb430",
                "maxFeePerGas": "0x7ffffffff",
                "maxPriorityFeePerGas": "0x7ffffffff",
                "signature": "0x7980544d044bc1202fed7edec96f2fa795ab8670b439935e6bbb5104e95d84ea32af8bff187913ff7eb2b442baab06d0c300273942e312332659ab0a194bbbe81c",
            }
            return {
                "jsonrpc": "2.0",
                "id": 1,
                "result": "0xa950a17ca1ed83e974fb1aa227360a007cb65f566518af117ffdbb04d8d2d524",
            }

    w3.provider.make_request.side_effect = make_request

    ret = aa_bundler.send_transaction(w3, tx)
    assert ret == "0xa950a17ca1ed83e974fb1aa227360a007cb65f566518af117ffdbb04d8d2d524"
