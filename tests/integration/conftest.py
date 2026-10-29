"""Integration fixtures: a throwaway Anvil chain with SecureFileShare deployed.

Each test session starts its own `anvil` on a free port, so the tests never touch
the chain in .chain/ or the addresses in .env.local. The tests are skipped when
anvil cannot be found; set ANVIL_BIN if it is not on PATH or in ~/.foundry/bin.

Users are fresh keystores (no scrypt, keys generated directly), funded with
anvil_setBalance. Every test registers its own files under random salts, so
tests do not depend on each other even though they share one chain.
"""

from __future__ import annotations

import itertools
import json
import os
import shutil
import socket
import subprocess
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from web3 import Web3

from app.chain.client import ABI_PATH, ChainClient
from app.chain.events import EventLog
from app.config import NetworkConfig
from app.crypto.keystore import UserKeys, generate_user_keys
from app.services.account import AccountService, Session
from app.services.models import ProtectedFile
from app.services.owner import OwnerService
from app.storage.object_store import LocalObjectStore
from scripts.deploy import deploy

CHAIN_ID = 31337
STARTUP_SECONDS = 15
FUNDING_WEI = 100 * 10**18


def _find_anvil() -> str | None:
    """ANVIL_BIN, then PATH, then Foundry's default install directory."""
    candidates = (os.environ.get("ANVIL_BIN"), shutil.which("anvil"), str(Path.home() / ".foundry" / "bin" / "anvil"))
    return next((path for path in candidates if path and Path(path).is_file()), None)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="session")
def anvil_url() -> Iterator[str]:
    """A private anvil for the whole session, terminated at the end."""
    anvil = _find_anvil()
    if anvil is None:
        pytest.skip("anvil not found: install Foundry or set ANVIL_BIN")
    port = _free_port()
    process = subprocess.Popen(
        [anvil, "--port", str(port), "--chain-id", str(CHAIN_ID), "--silent"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    try:
        _wait_until_ready(Web3(Web3.HTTPProvider(url)), process)
        yield url
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()


def _wait_until_ready(w3: Web3, process: subprocess.Popen[bytes]) -> None:
    """Poll until the RPC answers; fail at once if anvil exits."""
    deadline = time.monotonic() + STARTUP_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            pytest.fail(f"anvil exited with code {process.returncode}")
        if w3.is_connected():
            return
        time.sleep(0.1)
    pytest.fail(f"anvil did not answer within {STARTUP_SECONDS} s")


@pytest.fixture(scope="session")
def network(anvil_url: str) -> NetworkConfig:
    """Deploy with the same code path as scripts/deploy.py (Anvil's unlocked account 0)."""
    artifact = json.loads(ABI_PATH.read_text(encoding="utf-8"))
    deployment = deploy(Web3(Web3.HTTPProvider(anvil_url)), artifact, None, "")
    return NetworkConfig(
        name="local",
        rpc_url=anvil_url,
        chain_id=CHAIN_ID,
        contract_address=deployment.address,
        deploy_block=deployment.block_number,
    )


@pytest.fixture(scope="session")
def chain(network: NetworkConfig) -> ChainClient:
    return ChainClient.connect(network)


@pytest.fixture(scope="session")
def storage_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One store shared by every user, like a STORAGE_DIR shared by several GUI windows."""
    return tmp_path_factory.mktemp("storage")


@pytest.fixture(scope="session")
def make_session(chain: ChainClient, storage_dir: Path) -> Callable[..., Session]:
    """A new funded user; registered on-chain unless register=False. Each session has
    its own event log, as each GUI window would."""

    def make(*, register: bool = True, keys: UserKeys | None = None) -> Session:
        keys = keys or generate_user_keys()
        fund(chain, keys.address)
        session = Session(keys=keys, chain=chain, store=LocalObjectStore(storage_dir), events=EventLog(chain))
        if register:
            AccountService(session).register_keys()
        return session

    return make


def fund(chain: ChainClient, address: str, wei: int = FUNDING_WEI) -> None:
    """Set the balance directly; Anvil only."""
    chain.web3.provider.make_request("anvil_setBalance", [address, hex(wei)])


@pytest.fixture(scope="session")
def alice(make_session: Callable[..., Session]) -> Session:
    """File owner."""
    return make_session()


@pytest.fixture(scope="session")
def bob(make_session: Callable[..., Session]) -> Session:
    """Requester who gets approved."""
    return make_session()


@pytest.fixture(scope="session")
def carol(make_session: Callable[..., Session]) -> Session:
    """Second requester."""
    return make_session()


@pytest.fixture(scope="session")
def mallory(make_session: Callable[..., Session]) -> Session:
    """Registered user without any permission."""
    return make_session()


@pytest.fixture
def free_port() -> int:
    """A port nothing listens on."""
    return _free_port()


@pytest.fixture
def plaintext(tmp_path: Path) -> Path:
    """Random binary content under a name with a space in it."""
    path = tmp_path / "quarterly report.pdf"
    path.write_bytes(os.urandom(4096) + b"\x00end")
    return path


@pytest.fixture
def protected(alice: Session, plaintext: Path) -> ProtectedFile:
    """A new file owned by Alice, registered for this test only."""
    return OwnerService(alice).protect_file(plaintext, label="Q3 report")


@pytest.fixture
def make_protected(alice: Session, tmp_path: Path) -> Callable[..., ProtectedFile]:
    """More files owned by Alice, each with random content."""
    counter = itertools.count()

    def make(label: str = "") -> ProtectedFile:
        path = tmp_path / f"file-{next(counter)}.bin"
        path.write_bytes(os.urandom(1024))
        return OwnerService(alice).protect_file(path, label=label)

    return make
