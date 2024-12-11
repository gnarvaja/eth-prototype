import os
import signal
import subprocess
import sys
import time

import requests


def hardhat_node(hardhat_project_path, hostname="127.0.0.1", port=8545):
    """Starts the hardhat node on the given path and returns a function to stop it"""
    provider_uri = f"http://{hostname}:{port}"

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

    return terminate_node
