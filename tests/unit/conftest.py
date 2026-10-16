from __future__ import annotations

import pytest

from app.crypto import aead
from app.crypto.encoding import FileContext, compute_file_id
from app.crypto.keystore import UserKeys, generate_user_keys

CHAIN_ID = 31337
CONTRACT = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
SALT = bytes(range(32))


@pytest.fixture(scope="session")
def alice() -> UserKeys:
    """File owner."""
    return generate_user_keys()


@pytest.fixture(scope="session")
def bob() -> UserKeys:
    """Approved requester."""
    return generate_user_keys()


@pytest.fixture(scope="session")
def mallory() -> UserKeys:
    """Registered user without permission."""
    return generate_user_keys()


@pytest.fixture
def ctx(alice: UserKeys) -> FileContext:
    return FileContext(
        chain_id=CHAIN_ID,
        contract=CONTRACT,
        file_id=compute_file_id(alice.address, SALT),
        owner=alice.address,
    )


@pytest.fixture
def dek() -> bytes:
    return aead.generate_dek()
