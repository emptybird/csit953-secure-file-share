"""Network and directory settings (DESIGN.md 5.1).

Each network has its own git-ignored file, `.env.local` or `.env.sepolia`, made
from `.env.example`. Nothing chain-specific is hard-coded: the login screen
lists whichever files exist and the chosen one decides RPC, chain and contract.

    RPC_URL           http(s) endpoint; may embed an API key, so never print it whole
    CHAIN_ID          checked against the node on connect
    CONTRACT_ADDRESS  written by scripts/deploy.py
    DEPLOY_BLOCK      first block scanned for events
    EXPLORER_URL      optional, e.g. https://sepolia.etherscan.io
    STORAGE_DIR       optional, default storage/ (relative paths start at the project root)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from dotenv import dotenv_values

from app.crypto import EncodingError
from app.crypto.encoding import normalize_address

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_STORAGE_DIR = "storage"
KEYSTORE_DIR_NAME = "keystore"

_NETWORK_NAME = re.compile(r"[a-z0-9_-]{1,32}")
_ENV_PREFIX = ".env."
_TEMPLATE_SUFFIX = "example"


class ConfigError(ValueError):
    """A configuration file is missing or invalid; the message names the file and key."""


@dataclass(frozen=True)
class NetworkConfig:
    name: str
    rpc_url: str
    chain_id: int
    contract_address: str
    deploy_block: int
    explorer_url: str = ""

    @property
    def rpc_host(self) -> str:
        """Safe to display: the RPC URL itself may carry an API key."""
        return urlparse(self.rpc_url).hostname or "RPC endpoint"

    def tx_url(self, tx_hash: str) -> str:
        return f"{self.explorer_url}/tx/{tx_hash}" if self.explorer_url else ""

    def address_url(self, address: str) -> str:
        return f"{self.explorer_url}/address/{address}" if self.explorer_url else ""


@dataclass(frozen=True)
class AppConfig:
    network: NetworkConfig
    storage_dir: Path
    keystore_dir: Path


def available_networks(root: Path = ROOT_DIR) -> list[str]:
    """Names of the `.env.<name>` files present, e.g. ['local', 'sepolia']."""
    names = (path.name[len(_ENV_PREFIX) :] for path in root.glob(_ENV_PREFIX + "*") if path.is_file())
    return sorted(name for name in names if name != _TEMPLATE_SUFFIX and _NETWORK_NAME.fullmatch(name))


def load_config(network: str, root: Path = ROOT_DIR) -> AppConfig:
    if not _NETWORK_NAME.fullmatch(network) or network == _TEMPLATE_SUFFIX:
        raise ConfigError(f"Unknown network name {network!r}")
    env_path = root / f"{_ENV_PREFIX}{network}"
    if not env_path.is_file():
        raise ConfigError(f"{env_path.name} not found; copy .env.example to {env_path.name} and fill it in")
    values = {key: (value or "").strip() for key, value in dotenv_values(env_path).items()}
    return AppConfig(
        network=_network(network, values, env_path.name),
        storage_dir=_directory(values.get("STORAGE_DIR") or DEFAULT_STORAGE_DIR, root),
        keystore_dir=root / KEYSTORE_DIR_NAME,
    )


def _network(name: str, values: dict[str, str], source: str) -> NetworkConfig:
    contract = values.get("CONTRACT_ADDRESS", "")
    if not contract:
        raise ConfigError(f"CONTRACT_ADDRESS is empty in {source}; run scripts/deploy.py first")
    try:
        contract = normalize_address(contract)
    except EncodingError as exc:
        raise ConfigError(f"CONTRACT_ADDRESS in {source}: {exc}") from exc
    return NetworkConfig(
        name=name,
        rpc_url=_http_url(values.get("RPC_URL", ""), "RPC_URL", source, required=True),
        chain_id=_integer(values.get("CHAIN_ID", ""), "CHAIN_ID", source, minimum=1),
        contract_address=contract,
        deploy_block=_integer(values.get("DEPLOY_BLOCK") or "0", "DEPLOY_BLOCK", source, minimum=0),
        explorer_url=_http_url(values.get("EXPLORER_URL", ""), "EXPLORER_URL", source, required=False).rstrip("/"),
    )


def _http_url(value: str, key: str, source: str, *, required: bool) -> str:
    if not value:
        if required:
            raise ConfigError(f"{key} is missing in {source}")
        return ""
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ConfigError(f"{key} in {source} must be an http(s) URL")
    return value


def _integer(value: str, key: str, source: str, *, minimum: int) -> int:
    if not (value.isascii() and value.isdigit()) or int(value) < minimum:
        raise ConfigError(f"{key} in {source} must be an integer >= {minimum}")
    return int(value)


def _directory(value: str, root: Path) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else root / path
