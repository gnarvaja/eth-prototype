from dataclasses import replace
from queue import Queue
from threading import Event, Thread
from unittest.mock import MagicMock, patch

import pytest
from hexbytes import HexBytes
from web3.auto import w3
from web3.constants import HASH_ZERO

from ethproto import aa_bundler
from ethproto.test_utils import factories


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


user_operation = aa_bundler.UserOperation(
    sender=TEST_SENDER,
    nonce=0,
    init_code="0x",
    call_data=TEST_CALL_DATA,
    call_gas_limit=999999,
    verification_gas_limit=999999,
    pre_verification_gas=999999,
    max_fee_per_gas=1000000000,
    max_priority_fee_per_gas=1000000000,
    paymaster_and_data="0x",
    signature="0x",
)


def test_pack_user_operation():
    expected = aa_bundler.PackedUserOperation(
        sender=TEST_SENDER,
        nonce=0,
        init_code="0x",
        call_data=TEST_CALL_DATA,
        account_gas_limits="0x000000000000000000000000000f423f000000000000000000000000000f423f",
        pre_verification_gas=999999,
        gas_fees="0x0000000000000000000000003b9aca000000000000000000000000003b9aca00",
        paymaster_and_data="0x",
        signature="0x",
    )
    assert aa_bundler.PackedUserOperation.from_user_operation(user_operation) == expected


def test_hash_packed_user_operation():
    packed = aa_bundler.PackedUserOperation.from_user_operation(user_operation)
    assert packed.hash() == HexBytes("0xa2c19765d18b0d690c05b20061bd23d066201aff1833a51bd28af115fbd4bcd9")
    assert packed.hash_full(CHAIN_ID, ENTRYPOINT) == HexBytes(
        "0xb365ad4d366e9081718e926912da7a78a2faae592286fda0cc11923bd141b7cf"
    )


def test_sign_user_operation():
    signed = user_operation.sign(TEST_PRIVATE_KEY, CHAIN_ID, ENTRYPOINT)
    assert signed.signature == HexBytes(
        "0xb9b872bfe4e90f4628e8ec24879a5b01045f91da8457f3ce2b417d2e5774b508261ec1147a820e75a141cb61b884a78d7e88996ceddafb9a7016cfe7a48a1f4f1b"  # noqa
    )


def test_sign_user_operation_gas_diff():
    user_operation_2 = replace(
        user_operation, max_priority_fee_per_gas=user_operation.max_priority_fee_per_gas - 1
    ).sign(TEST_PRIVATE_KEY, CHAIN_ID, ENTRYPOINT)
    assert user_operation_2.signature == HexBytes(
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
    fetch_nonce_mock.return_value = 123
    assert aa_bundler.Bundler(
        FAIL_IF_USED, nonce_mode=aa_bundler.NonceMode.FIXED_KEY_LOCAL_NONCE
    ).get_nonce_and_key(factories.Tx(nonce_key=12, from_=TEST_SENDER), fetch=True) == (12, 123)
    fetch_nonce_mock.assert_called_once_with(FAIL_IF_USED, TEST_SENDER, ENTRYPOINT, 12)
    randint_mock.assert_not_called()


@patch.object(aa_bundler.random, "randint")
@patch.object(aa_bundler, "fetch_nonce")
def test_get_nonce_fetch_always_mode(fetch_nonce_mock, randint_mock):
    # Test nonce_mode=NonceMode.FIXED_KEY_FETCH_ALWAYS
    fetch_nonce_mock.return_value = 111
    assert aa_bundler.Bundler(
        FAIL_IF_USED, nonce_mode=aa_bundler.NonceMode.FIXED_KEY_FETCH_ALWAYS
    ).get_nonce_and_key(factories.Tx(from_=TEST_SENDER, nonce_key=22)) == (22, 111)
    fetch_nonce_mock.assert_called_once_with(FAIL_IF_USED, TEST_SENDER, ENTRYPOINT, 22)
    randint_mock.assert_not_called()
    fetch_nonce_mock.reset_mock()


@patch.object(aa_bundler.random, "randint")
@patch.object(aa_bundler, "fetch_nonce")
def test_get_nonce_nonce_key_in_tx(fetch_nonce_mock, randint_mock):
    # Test nonce_mode=NonceMode.FIXED_KEY_LOCAL_NONCE
    assert aa_bundler.Bundler(
        FAIL_IF_USED, nonce_mode=aa_bundler.NonceMode.FIXED_KEY_LOCAL_NONCE
    ).get_nonce_and_key(factories.Tx(nonce_key=22)) == (22, 0)
    randint_mock.assert_not_called()
    fetch_nonce_mock.assert_not_called()

    # Same if nonce_mode=NonceMode.RANDOM_KEY but nonceKey in the tx
    assert aa_bundler.Bundler(FAIL_IF_USED, nonce_mode=aa_bundler.NonceMode.RANDOM_KEY).get_nonce_and_key(
        factories.Tx(nonce_key=22)
    ) == (22, 0)
    randint_mock.assert_not_called()
    fetch_nonce_mock.assert_not_called()


@patch.object(aa_bundler.random, "randint")
@patch.object(aa_bundler, "fetch_nonce")
def test_get_nonce_random_key_mode(fetch_nonce_mock, randint_mock):
    # If nonce_mode=NonceMode.RANDOM_KEY creates a random key and stores it
    randint_mock.return_value = 444
    assert aa_bundler.Bundler(FAIL_IF_USED, nonce_mode=aa_bundler.NonceMode.RANDOM_KEY).get_nonce_and_key(
        factories.Tx()
    ) == (444, 0)
    fetch_nonce_mock.assert_not_called()
    randint_mock.assert_called_with(1, 2**192 - 1)
    randint_mock.reset_mock()
    assert aa_bundler.RANDOM_NONCE_KEY.key == 444
    aa_bundler.RANDOM_NONCE_KEY.key = None  # cleanup


@patch.object(aa_bundler.random, "randint")
@patch.object(aa_bundler, "fetch_nonce")
def test_get_nonce_with_local_cache(fetch_nonce_mock, randint_mock):
    with patch.object(aa_bundler, "NONCE_CACHE", new={55: 33}):
        # Test nonce_mode=NonceMode.FIXED_KEY_LOCAL_NONCE
        assert aa_bundler.Bundler(
            FAIL_IF_USED,
            nonce_mode=aa_bundler.NonceMode.FIXED_KEY_LOCAL_NONCE,
            fixed_nonce_key=55,
        ).get_nonce_and_key(factories.Tx()) == (55, 33)
        randint_mock.assert_not_called()
        fetch_nonce_mock.assert_not_called()


def test_send_transaction():
    w3 = MagicMock()
    w3.eth.chain_id = CHAIN_ID

    tx = aa_bundler.Tx(
        value=0,
        target="0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
        data=HexBytes(
            "0x095ea7b30000000000000000000000007ace242f32208d836a2245df957c08547059bf45ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"  # noqa
        ),
        from_="0xE8B412158c205B0F605e0FC09dCdA27d3F140FE9",
        chain_id=137,
    )

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

    bundler = aa_bundler.Bundler(
        w3,
        executor_pk=TEST_PRIVATE_KEY,
        nonce_mode=aa_bundler.NonceMode.FIXED_KEY_LOCAL_NONCE,
        fixed_nonce_key=0,
    )
    make_request_mock = MagicMock(side_effect=make_request)
    get_base_fee_mock = MagicMock(return_value=0)
    bundler.bundler.provider.make_request = make_request_mock
    bundler.get_base_fee = get_base_fee_mock

    ret = bundler.send_transaction(tx)
    get_base_fee_mock.assert_called_once_with()
    assert aa_bundler.NONCE_CACHE[0] == 1
    assert ret == {"userOpHash": "0xa950a17ca1ed83e974fb1aa227360a007cb65f566518af117ffdbb04d8d2d524"}


def test_random_key_nonces_are_thread_safe():
    queue = Queue()
    event = Event()

    bundler = aa_bundler.Bundler(FAIL_IF_USED, nonce_mode=aa_bundler.NonceMode.RANDOM_KEY)

    def worker():
        event.wait()  # Get all threads running at the same time
        nonce_key, nonce = bundler.get_nonce_and_key(factories.Tx())
        aa_bundler.consume_nonce(nonce_key, nonce)
        queue.put(bundler.get_nonce_and_key(factories.Tx()))

    threads = [Thread(target=worker) for _ in range(15)]
    for thread in threads:
        thread.start()

    # Fire all threads at once
    event.set()
    for thread in threads:
        thread.join()

    nonces = {}

    while not queue.empty():
        nonce_key, nonce = queue.get_nowait()
        # Each thread got a different key
        assert nonce_key not in nonces
        nonces[nonce_key] = nonce

    # All nonces are the same
    assert all(nonce == 1 for nonce in nonces.values())


@pytest.mark.vcr
def test_build_user_operation():
    tx = aa_bundler.Tx(
        value=0,
        chain_id=137,
        from_="0xE8B412158c205B0F605e0FC09dCdA27d3F140FE9",
        target="0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
        data=HexBytes(
            "0x095ea7b30000000000000000000000007ace242f32208d836a2245df957c08547059bf45ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"  # noqa
        ),
    )

    userop = aa_bundler.Bundler(
        w3,
        nonce_mode=aa_bundler.NonceMode.FIXED_KEY_LOCAL_NONCE,
        fixed_nonce_key=0xAE85C374AE0606ED34D0EE009A9CA43A757A8A46A32451,
        executor_pk=TEST_PRIVATE_KEY,
        entrypoint=ENTRYPOINT,
    ).build_user_operation(tx)

    assert userop.as_dict() == {
        "callData": (
            "0xb61d27f60000000000000000000000002791bca1f2de4661ed88a30c99a7a9449aa84174"
            "00000000000000000000000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000006000000000000000000000"
            "00000000000000000000000000000000000000000044095ea7b30000000000000000000000"
            "007ace242f32208d836a2245df957c08547059bf45ffffffffffffffffffffffffffffffff"
            "ffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000"
            "00000000000000"
        ),
        "callGasLimit": "0xcbb8",
        "maxFeePerGas": "0x89e80ffda",
        "maxPriorityFeePerGas": "0x7aef40a00",
        "nonce": "0xae85c374ae0606ed34d0ee009a9ca43a757a8a46a324510000000000000000",
        "preVerificationGas": "0xb5c8",
        "sender": "0xE8B412158c205B0F605e0FC09dCdA27d3F140FE9",
        "signature": (
            "0xfffffffffffffffffffffffffffffff00000000000000000000000000000000"
            "07aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c"
        ),
        "verificationGasLimit": "0x1365b",
    }
