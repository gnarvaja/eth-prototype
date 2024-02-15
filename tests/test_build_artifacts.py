import os

import pytest

from ethproto.build_artifacts import ArtifactLibrary

# Get current file path
BASE_PATH = os.path.dirname(os.path.abspath(__file__))
HARDHAT_PROJECT = os.path.join(BASE_PATH, "hardhat-project")
JSON_PROJECT = os.path.join(BASE_PATH, "json-project")


def test_artifact_library_fullpath_lookup():
    library = ArtifactLibrary(os.path.join(HARDHAT_PROJECT, "artifacts"))

    counter_build = library.get_artifact("contracts/Counter.sol")
    assert counter_build.contract_name == "Counter"
    assert counter_build.link_references == {}


def test_artifact_library_fullpath_lookup_multiple_lookup_paths():
    library = ArtifactLibrary(
        os.path.join(HARDHAT_PROJECT, "artifacts"),
        os.path.join(HARDHAT_PROJECT, "artifacts2"),
    )

    counter_build = library.get_artifact("contracts/Counter.sol")
    assert counter_build.contract_name == "Counter"
    assert counter_build.link_references == {}

    contract_build = library.get_artifact("TestCurrency.sol")
    assert contract_build.contract_name == "TestCurrency"
    assert contract_build.link_references == {}


def test_artifact_library_fullpath_notfound():
    library = ArtifactLibrary(os.path.join(HARDHAT_PROJECT, "artifacts"))

    with pytest.raises(FileNotFoundError):
        library.get_artifact("contracts/NonExistent.sol")


def test_artifact_library_recursive_lookup():
    library = ArtifactLibrary(os.path.join(HARDHAT_PROJECT, "artifacts"))

    counter_build = library.get_artifact_by_name("Counter")
    assert counter_build.contract_name == "Counter"
    assert counter_build.link_references == {}


def test_artifact_library_recursive_lookup_multiple_paths():
    library = ArtifactLibrary(
        os.path.join(HARDHAT_PROJECT, "artifacts"),
        os.path.join(HARDHAT_PROJECT, "artifacts2"),
    )

    counter_build = library.get_artifact_by_name("Counter")
    assert counter_build.contract_name == "Counter"
    assert counter_build.link_references == {}

    counter_build = library.get_artifact_by_name("TestCurrency")
    assert counter_build.contract_name == "TestCurrency"
    assert counter_build.link_references == {}


def test_artifact_library_cache():
    library = ArtifactLibrary(
        os.path.join(HARDHAT_PROJECT, "artifacts"),
        os.path.join(HARDHAT_PROJECT, "artifacts2"),
    )

    counter_build = library.get_artifact("contracts/Counter.sol")
    counter_build_2 = library.get_artifact("contracts/Counter.sol")
    assert counter_build is counter_build_2

    testcurrency_build = library.get_artifact_by_name("TestCurrency")
    testcurrency_build_2 = library.get_artifact_by_name("TestCurrency")
    assert testcurrency_build is testcurrency_build_2


def test_artifact_link_with_no_libraries():
    library = ArtifactLibrary(os.path.join(HARDHAT_PROJECT, "artifacts"))

    artifact = library.get_artifact("contracts/Counter.sol")
    linked_artifact = artifact.link({})

    assert artifact.bytecode == linked_artifact.bytecode
    assert artifact.deployed_bytecode == linked_artifact.deployed_bytecode


def test_artifact_link_with_libraries():
    library = ArtifactLibrary(os.path.join(HARDHAT_PROJECT, "artifacts"))

    artifact = library.get_artifact("contracts/CounterWithLibrary.sol")
    linked_artifact = artifact.link({"Count": "0x1234567890123456789012345678901234567890"})

    assert linked_artifact.bytecode == artifact.bytecode.replace(
        "__$69fad24a0434cdadf4afcd45c858c7bb14$__",
        "1234567890123456789012345678901234567890",
    )
    assert linked_artifact.deployed_bytecode == artifact.deployed_bytecode.replace(
        "__$69fad24a0434cdadf4afcd45c858c7bb14$__",
        "1234567890123456789012345678901234567890",
    )


def test_artifact_link_missing_addresses():
    library = ArtifactLibrary(os.path.join(HARDHAT_PROJECT, "artifacts"))

    artifact = library.get_artifact("contracts/CounterWithLibrary.sol")
    with pytest.raises(ValueError, match="Missing library address for Count"):
        artifact.link({})


def test_artifact_libraries_generator():
    library = ArtifactLibrary(os.path.join(HARDHAT_PROJECT, "artifacts"))

    artifact = library.get_artifact("contracts/CounterWithLibrary.sol")
    libraries = list(artifact.libraries())
    assert libraries == [("Count", "contracts/Count.sol")]

    artifact_with_no_libraries = library.get_artifact("contracts/Counter.sol")
    libraries = list(artifact_with_no_libraries.libraries())
    assert libraries == []
