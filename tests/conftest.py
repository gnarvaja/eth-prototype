import os
import signal
import subprocess
import sys
import time

import pytest
import requests
from vcr import VCR
from web3.auto import w3
from web3.middleware import ExtraDataToPOAMiddleware

from . import vcr_utils


def pytest_configure(config):
    if os.environ.get("TEST_ENV", None) != "web3py":
        return

    from ethproto import w3wrappers, wrappers

    wrappers.DEFAULT_PROVIDER = "w3"
    w3wrappers.CONTRACT_JSON_PATH = ["tests/hardhat-project"]


@pytest.fixture(scope="module")
def local_node_provider(hardhat_node):
    """Resets the provider for each module. Mainly for addressbook and contract map cleanse"""
    if os.environ.get("TEST_ENV", None) == "web3py":
        from web3 import Web3

        from ethproto import w3wrappers, wrappers

        wrappers.register_provider("w3", w3wrappers.W3Provider(Web3(Web3.HTTPProvider(hardhat_node))))
        yield
        wrappers.register_provider("w3", w3wrappers.W3Provider(w3))
        return
    yield


@pytest.fixture(autouse=True, scope="session")
def w3_poa_middleware():
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)


def pytest_recording_configure(config, vcr: VCR):
    vcr.register_matcher("json_rpc", vcr_utils.json_rpc_matcher)
    vcr.before_record_request = vcr_utils.before_record_request


@pytest.fixture(autouse=True)
def vcr_config():
    return {"match_on": ["json_rpc"], "allow_playback_repeats": True}


@pytest.fixture(scope="session")
def hardhat_node():
    hardhat_project_path = "tests/hardhat-project"
    provider_uri = "http://127.0.0.1:8545"

    # Compile the Hardhat project
    compile_process = subprocess.run(
        ["npx", "hardhat", "compile"], cwd=hardhat_project_path, capture_output=True, text=True
    )
    if compile_process.returncode != 0:
        raise RuntimeError(f"Hardhat compilation failed: {compile_process.stderr}")

    # Start the Hardhat node
    node_process = subprocess.Popen(
        ["npx", "hardhat", "node"],
        start_new_session=True,
        cwd=hardhat_project_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        text=True,
    )

    # Wait for the node to be ready by checking eth_chainId
    def is_node_ready():
        try:
            response = requests.post(
                provider_uri,
                json={"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1},
                timeout=1,
            )
            return response.status_code == 200
        except Exception:
            return False

    def terminate_node():
        node_process.terminate()
        os.killpg(os.getpgid(node_process.pid), signal.SIGTERM)
        try:
            node_process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            print("Hardhat node did not terminate in time, killing the whole process group", file=sys.stderr)
            os.killpg(os.getpgid(node_process.pid), signal.SIGKILL)

    # Retry mechanism to check node readiness
    max_attempts = 20
    for _ in range(max_attempts):
        if is_node_ready():
            break
        time.sleep(0.5)
    else:
        terminate_node()
        raise RuntimeError("Hardhat node did not become ready in time")

    # Did we actually connect to our process, or did it fail because another node was already started?
    try:
        _, stderr = node_process.communicate(timeout=2)
        raise RuntimeError(f"Hardhat node process exited with code {node_process.returncode}: {stderr}")
    except subprocess.TimeoutExpired:
        # We connected to our process, everything is good
        pass

    try:
        yield provider_uri
    finally:
        terminate_node()
