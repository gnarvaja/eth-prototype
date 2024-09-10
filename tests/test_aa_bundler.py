from unittest.mock import MagicMock, patch

from hexbytes import HexBytes
from web3.constants import HASH_ZERO

from ethproto import aa_bundler


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

TEST_SENDER = "0x8961423b54f06bf6D57F8dD3dD1184FA6F3aac3f"

user_operation = {
    "sender": TEST_SENDER,
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
        "sender": TEST_SENDER,
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
    assert hash == HexBytes("0xa2c19765d18b0d690c05b20061bd23d066201aff1833a51bd28af115fbd4bcd9")
    hash = aa_bundler.hash_packed_user_operation(packed, CHAIN_ID, ENTRYPOINT)
    assert hash == HexBytes("0xb365ad4d366e9081718e926912da7a78a2faae592286fda0cc11923bd141b7cf")


def test_sign_user_operation():
    signature = aa_bundler.sign_user_operation(TEST_PRIVATE_KEY, user_operation, CHAIN_ID, ENTRYPOINT)
    assert signature == HexBytes(
        "0xb9b872bfe4e90f4628e8ec24879a5b01045f91da8457f3ce2b417d2e5774b508261ec1147a820e75a141cb61b884a78d7e88996ceddafb9a7016cfe7a48a1f4f1b"  # noqa
    )


def test_sign_user_operation_gas_diff():
    user_operation_2 = dict(user_operation)
    user_operation_2["maxPriorityFeePerGas"] -= 1
    signature = aa_bundler.sign_user_operation(TEST_PRIVATE_KEY, user_operation_2, CHAIN_ID, ENTRYPOINT)
    assert signature == HexBytes(
        "0x8162479d2dbd18d7fe93a2f51e283021d6e4eae4f57d20cdd553042723a0b0ea690ab3903d45126b0047da08ab53dfdf86656e4f258ac4936ba96a759ccb77f61b"  # noqa
    )


def test_make_nonce():
    assert aa_bundler.make_nonce(0, 0) == 0
    assert aa_bundler.make_nonce(0, 1) == 1
    assert aa_bundler.make_nonce(1, 1) == (1 << 64) + 1


FAIL_IF_USED = object()


@patch.object(aa_bundler.random, "randint")
@patch.object(aa_bundler, "fetch_nonce")
def test_get_nonce_force_fetch(fetch_nonce_mock, randint_mock):
    # Test fetch=True
    fetch_nonce_mock.return_value = 123
    assert aa_bundler.get_nonce_and_key(
        FAIL_IF_USED,
        {"nonceKey": 12, "from": TEST_SENDER},
        nonce_mode=aa_bundler.NonceMode.FIXED_KEY_LOCAL_NONCE,
        fetch=True,
    ) == (12, 123)
    fetch_nonce_mock.assert_called_once_with(FAIL_IF_USED, TEST_SENDER, ENTRYPOINT, 12)
    randint_mock.assert_not_called()


@patch.object(aa_bundler.random, "randint")
@patch.object(aa_bundler, "fetch_nonce")
def test_get_nonce_fetch_always_mode(fetch_nonce_mock, randint_mock):
    # Test nonce_mode=NonceMode.FIXED_KEY_FETCH_ALWAYS
    fetch_nonce_mock.return_value = 111
    assert aa_bundler.get_nonce_and_key(
        FAIL_IF_USED,
        {"nonceKey": 22, "from": TEST_SENDER},
        nonce_mode=aa_bundler.NonceMode.FIXED_KEY_FETCH_ALWAYS,
    ) == (22, 111)
    fetch_nonce_mock.assert_called_once_with(FAIL_IF_USED, TEST_SENDER, ENTRYPOINT, 22)
    randint_mock.assert_not_called()
    fetch_nonce_mock.reset_mock()


@patch.object(aa_bundler.random, "randint")
@patch.object(aa_bundler, "fetch_nonce")
def test_get_nonce_nonce_key_in_tx(fetch_nonce_mock, randint_mock):
    # Test nonce_mode=NonceMode.FIXED_KEY_LOCAL_NONCE
    assert aa_bundler.get_nonce_and_key(
        FAIL_IF_USED,
        {"nonceKey": 22, "from": TEST_SENDER},
        nonce_mode=aa_bundler.NonceMode.FIXED_KEY_LOCAL_NONCE,
    ) == (22, 0)
    randint_mock.assert_not_called()
    fetch_nonce_mock.assert_not_called()

    # Same if nonce_mode=NonceMode.RANDOM_KEY but nonceKey in the tx
    assert aa_bundler.get_nonce_and_key(
        FAIL_IF_USED,
        {"nonceKey": 22, "from": TEST_SENDER},
        nonce_mode=aa_bundler.NonceMode.RANDOM_KEY,
    ) == (22, 0)
    randint_mock.assert_not_called()
    fetch_nonce_mock.assert_not_called()


@patch.object(aa_bundler.random, "randint")
@patch.object(aa_bundler, "fetch_nonce")
def test_get_nonce_random_key_mode(fetch_nonce_mock, randint_mock):
    # If nonce_mode=NonceMode.RANDOM_KEY creates a random key and stores it
    randint_mock.return_value = 444
    assert aa_bundler.get_nonce_and_key(
        FAIL_IF_USED,
        {"from": TEST_SENDER},
        nonce_mode=aa_bundler.NonceMode.RANDOM_KEY,
    ) == (444, 0)
    fetch_nonce_mock.assert_not_called()
    randint_mock.assert_called_with(1, 2**192 - 1)
    randint_mock.reset_mock()
    assert aa_bundler.RANDOM_NONCE_KEY == 444
    aa_bundler.RANDOM_NONCE_KEY = None  # cleanup


@patch.object(aa_bundler.random, "randint")
@patch.object(aa_bundler, "fetch_nonce")
def test_get_nonce_with_local_cache(fetch_nonce_mock, randint_mock):
    with patch.object(aa_bundler, "AA_BUNDLER_NONCE_KEY", new=55), patch.object(
        aa_bundler, "NONCE_CACHE", new={55: 33}
    ):
        # Test nonce_mode=NonceMode.FIXED_KEY_LOCAL_NONCE
        assert aa_bundler.get_nonce_and_key(
            FAIL_IF_USED,
            {"from": TEST_SENDER},
            nonce_mode=aa_bundler.NonceMode.FIXED_KEY_LOCAL_NONCE,
        ) == (55, 33)
        randint_mock.assert_not_called()
        fetch_nonce_mock.assert_not_called()


@patch.object(aa_bundler, "AA_BUNDLER_NONCE_MODE", new=aa_bundler.NonceMode.FIXED_KEY_LOCAL_NONCE)
@patch.object(aa_bundler, "get_base_fee")
def test_send_transaction(get_base_fee_mock):
    get_base_fee_mock.return_value = 0
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
                "callData": "0xb61d27f60000000000000000000000002791bca1f2de4661ed88a30c99a7a9449aa84174000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044095ea7b30000000000000000000000007ace242f32208d836a2245df957c08547059bf45ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000",  # noqa
                "signature": "0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c",  # noqa
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
                "callData": "0xb61d27f60000000000000000000000002791bca1f2de4661ed88a30c99a7a9449aa84174000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000044095ea7b30000000000000000000000007ace242f32208d836a2245df957c08547059bf45ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000",  # noqa
                "callGasLimit": "0xcbb8",
                "verificationGasLimit": "0x13664",
                "preVerificationGas": "0xb430",
                "maxFeePerGas": "0x7ffffffff",
                "maxPriorityFeePerGas": "0x7ffffffff",
                "signature": "0x7980544d044bc1202fed7edec96f2fa795ab8670b439935e6bbb5104e95d84ea32af8bff187913ff7eb2b442baab06d0c300273942e312332659ab0a194bbbe81c",  # noqa
            }
            return {
                "jsonrpc": "2.0",
                "id": 1,
                "result": "0xa950a17ca1ed83e974fb1aa227360a007cb65f566518af117ffdbb04d8d2d524",
            }

    w3.provider.make_request.side_effect = make_request

    ret = aa_bundler.send_transaction(w3, tx)
    get_base_fee_mock.assert_called_once_with(w3)
    assert aa_bundler.NONCE_CACHE[0] == 1
    assert ret == {"userOpHash": "0xa950a17ca1ed83e974fb1aa227360a007cb65f566518af117ffdbb04d8d2d524"}
