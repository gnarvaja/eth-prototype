"""Helper classes to use hardhat build artifacts from python"""

import json
import os
import os.path
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple, Union

LIBRARY_PLACEHOLDER_MATCHER = re.compile(r"__\$[0-9a-f]{34}\$__")

CONTRACT_REF_MATCHER = re.compile(r"^(?:(?P<package>.*)/)?(?P<contract>[^@]+)(?:@(?P<version>.+))?$")

VERSION_MATCHER = re.compile(r"^\d+\.\d+\.\d+$")


@dataclass
class Artifact:
    contract_name: str
    abi: list
    bytecode: str
    deployed_bytecode: str
    link_references: dict
    deployed_link_references: dict

    def __init__(self, **kwargs):
        self.contract_name = kwargs["contractName"]
        self.abi = kwargs["abi"]
        self.bytecode = kwargs["bytecode"]
        self.deployed_bytecode = kwargs["deployedBytecode"]
        self.link_references = kwargs.get("linkReferences", {})
        self.deployed_link_references = kwargs.get("deployedLinkReferences", {})

    def link(self, libraries: dict) -> "Artifact":
        """Returns a new artifact with the external libraries linked

        Libraries is a dictionary of the form {library_name: address}
        """
        bytecode = self._replace_link_references(self.bytecode, self.link_references, libraries)
        deployed_bytecode = self._replace_link_references(
            self.deployed_bytecode, self.deployed_link_references, libraries
        )
        return Artifact(
            contractName=self.contract_name,
            abi=self.abi,
            bytecode=bytecode,
            deployedBytecode=deployed_bytecode,
            linkReferences=self.link_references,
            deployedLinkReferences=self.deployed_link_references,
        )

    def libraries(self) -> Tuple[str, str]:
        """Generates a tuple of (library, source) for each library reference in the artifact"""
        for source, libs in self.link_references.items():
            for lib in libs.keys():
                yield lib, source

    def _replace_link_references(self, bytecode: str, link_references: dict, libraries: dict) -> str:
        # remove 0x prefix if present
        bytecode = bytecode[2:] if bytecode.startswith("0x") else bytecode

        for libs in link_references.values():
            for lib, lib_refs in libs.items():
                try:
                    address = libraries[lib]
                except KeyError:
                    raise ValueError(f"Missing library address for {lib}")
                address = address[2:] if address.startswith("0x") else address

                assert len(address) == 40  # Sanity check

                for ref in lib_refs:
                    # 2 nibbles -> 1 byte
                    start = ref["start"] * 2
                    length = ref["length"] * 2

                    # Sanity check
                    assert LIBRARY_PLACEHOLDER_MATCHER.match(
                        bytecode[start : start + length]
                    ), f"Unexpected placeholder at position {start}: {bytecode[start:start + length]}"

                    # Replace the placeholder with the actual address
                    bytecode = bytecode[:start] + address + bytecode[start + length :]

        # Return value always has 0x prefix
        return "0x" + bytecode

    def __str__(self):
        return f"Artifact({self.contract_name})"

    def __repr__(self):
        return f"Artifact({self.contract_name})"


class ArtifactLibrary:
    def __init__(self, *paths: Tuple[Union[str, Path]]):
        self.lookup_paths = [Path(p).absolute() for p in paths]
        self._fullpath_cache = {}
        self._name_cache = {}
        self._ref_cache = None

    def get_artifact(self, contract: str) -> Artifact:
        """Returns a build artifact by full contract path

        This method is compatible with hardhat's artifact structure.

        Examples:

        >>> library = ArtifactLibrary("./artifacts")
        >>> counter_build = library.get_artifact("contracts/Counter.sol")
        >>> proxy_build = library.get_artifact("@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol")
        """
        contract = Path(os.path.normpath(contract))

        if contract not in self._fullpath_cache:
            for path in self.lookup_paths:
                build_artifact_path = path / contract / contract.with_suffix(".json").name
                if build_artifact_path.exists():
                    with open(build_artifact_path) as f:
                        self._fullpath_cache[contract] = Artifact(**json.load(f))

            if contract not in self._fullpath_cache:
                raise FileNotFoundError(f"Could not find artifact for {contract} on {self.lookup_paths}")

        return self._fullpath_cache[contract]

    def get_artifact_by_name(self, contract_name: str) -> Artifact:
        """Returns a build artifact by looking for a matching contract name

        Example:

        >>> library = ArtifactLibrary("./artifacts")
        >>> counter_build = library.get_artifact_by_name("Counter")
        """
        if contract_name not in self._name_cache:
            for path in self.lookup_paths:
                for dirpath, _, filenames in os.walk(path):
                    if f"{contract_name}.json" in filenames:
                        with open(Path(dirpath) / f"{contract_name}.json") as f:
                            self._name_cache[contract_name] = Artifact(**json.load(f))

            if contract_name not in self._name_cache:
                raise FileNotFoundError(f"Could not find artifact for {contract_name} on {self.lookup_paths}")

        return self._name_cache[contract_name]

    def _load_ref_cache(self):
        self._ref_cache = {}
        for path in self.lookup_paths:
            path = Path(path)
            json_files = path.rglob("*.json")

            for json_file in json_files:
                # Skip build-info and debug files
                if json_file.parent.stem == "build-info" or json_file.stem.endswith(".dbg"):
                    continue

                parts = json_file.parts[len(path.parts) - 1 :]

                # Find the first parent named either "build" or "artifacts"
                try:
                    build_idx = next(i for i, part in enumerate(parts) if part in ("build", "artifacts"))
                except StopIteration:
                    continue

                if build_idx == 0:
                    # Our lookup path is already a build directory, we're probably looking at a hardhat build output
                    version = "local"
                else:
                    # If we have a version number right before the build directory, we're probably looking at a
                    # verifiable binaries directory
                    version = parts[build_idx - 1]
                    if not VERSION_MATCHER.match(version):
                        version = "local"

                if version == "local":
                    # For hardhat output dir, package is everything up to "contracts"
                    try:
                        package = "/".join(parts[build_idx + 1 : parts.index("contracts")])
                    except ValueError:
                        # There are exceptions, like @openzeppelin/contracts-upgradeable
                        # For those the package is everythin up to the contract directory
                        package = "/".join(parts[build_idx + 1 : -2])

                else:
                    # For verifiable binaries dir, package is everything up to version
                    package = "/".join(parts[1 : build_idx - 1])

                if json_file.stem not in self._ref_cache:
                    self._ref_cache[json_file.stem] = []
                self._ref_cache[json_file.stem].append(
                    {
                        "path": json_file,
                        "package": package,
                        "version": version,
                    }
                )

    def _find_ref(self, contract_ref: str):
        if self._ref_cache is None:
            self._load_ref_cache()

        ref_match = CONTRACT_REF_MATCHER.match(contract_ref)
        if not ref_match:
            raise ValueError(f"Invalid contract reference: {contract_ref}")

        contract = ref_match.group("contract")
        if contract not in self._ref_cache:
            return None

        ref = self._ref_cache[contract]

        package = ref_match.group("package")
        if package:
            ref = [r for r in ref if r["package"] == package]

        version = ref_match.group("version")
        if version:
            ref = [r for r in ref if r["version"] == version]

        if not ref:
            return None

        # Sort by version ascending, forcing local to be last
        ref = sorted(
            ref,
            key=lambda x: (
                x["version"] == "local",
                tuple(map(int, x["version"].split("."))) if x["version"] != "local" else None,
            ),
        )[-1]

        return ref

    def get_artifact_by_ref(self, contract_ref: str) -> Artifact:
        """Returns a build artifact by looking for a matching contract reference.

        This is compatible with the verifiable binaries structure.

        Accepts the following kind of references:

        - <ContractClass>
        - <ContractClass>@<version>
        - <package>/<ContractClass>
        - <package>/<ContractClass>@<version>

        If version is not specified it uses the latest version available.

        Calling with contract_ref <ContractClass>@local is the same as calling get_artifact_by_name(<ContractClass>).
        """
        ref = self._find_ref(contract_ref)

        if ref is None:
            raise FileNotFoundError(f"Could not find artifact for {contract_ref} on {self.lookup_paths}")

        with open(ref["path"]) as f:
            return Artifact(**json.load(f))
