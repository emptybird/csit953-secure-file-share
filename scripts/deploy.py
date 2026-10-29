"""Build, export and deploy the SecureFileShare contract.

    python scripts/deploy.py --network local
    python scripts/deploy.py --network sepolia --keystore ~/.foundry/keystores/deployer
    python scripts/deploy.py --export-only

Without --keystore the first unlocked account of the node is used, which on
Anvil is a public development account. On Sepolia pass an encrypted Ethereum
keystore (e.g. made by `cast wallet import deployer --interactive`); its
password is read with getpass and never echoed.
"""

from __future__ import annotations

import argparse
import getpass
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from dotenv import dotenv_values, set_key
from eth_account import Account
from eth_account.signers.local import LocalAccount
from web3 import Web3
from web3.exceptions import Web3Exception

ROOT_DIR = Path(__file__).resolve().parent.parent
CONTRACTS_DIR = ROOT_DIR / "contracts"
CONTRACT_NAME = "SecureFileShare"
FORGE_ARTIFACT = CONTRACTS_DIR / "out" / f"{CONTRACT_NAME}.sol" / f"{CONTRACT_NAME}.json"
APP_ARTIFACT = ROOT_DIR / "app" / "chain" / "abi" / f"{CONTRACT_NAME}.json"

NETWORKS = ("local", "sepolia")
RPC_TIMEOUT_SECONDS = 30
RECEIPT_TIMEOUT_SECONDS = 300
MAX_KEYSTORE_BYTES = 64 * 1024


class DeployError(RuntimeError):
    """Deployment cannot continue; the message is shown to the user."""


@dataclass(frozen=True)
class NetworkConfig:
    """The part of `.env.<network>` that deployment needs."""

    env_path: Path
    rpc_url: str
    chain_id: int
    explorer_url: str


@dataclass(frozen=True)
class Deployment:
    address: str
    tx_hash: str
    block_number: int
    gas_used: int


def main(argv: list[str] | None = None) -> int:
    """Build and export, then deploy and record the address. Returns the exit code."""
    args = _parse_args(argv)
    try:
        artifact = build_and_export()
        if args.export_only:
            return 0
        config = load_network_config(ROOT_DIR / f".env.{args.network}")
        w3 = connect(config)
        deployment = deploy(w3, artifact, args.keystore, config.explorer_url)
        record_deployment(config.env_path, deployment)
        _print_summary(deployment, config)
    except DeployError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


# ------------------------------------------------------------------ artifact


def build_and_export() -> dict:
    """Run `forge build` and copy ABI + bytecode to the app; reuse the copy if forge is missing."""
    forge = shutil.which("forge")
    if forge is None:
        if not APP_ARTIFACT.is_file():
            raise DeployError(f"forge is not installed and {_rel(APP_ARTIFACT)} does not exist")
        print(f"forge not found; using the committed {_rel(APP_ARTIFACT)}")
        return _read_json(APP_ARTIFACT)

    try:
        subprocess.run([forge, "build"], cwd=CONTRACTS_DIR, check=True)
    except subprocess.CalledProcessError as exc:
        raise DeployError(f"forge build failed with exit code {exc.returncode}") from exc

    compiled = _read_json(FORGE_ARTIFACT)
    artifact = {
        "contractName": CONTRACT_NAME,
        "compiler": compiled["metadata"]["compiler"]["version"],
        "abi": compiled["abi"],
        "bytecode": compiled["bytecode"]["object"],
    }
    APP_ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    APP_ARTIFACT.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(f"exported ABI and bytecode to {_rel(APP_ARTIFACT)}")
    return artifact


# ------------------------------------------------------------------- network


def load_network_config(env_path: Path) -> NetworkConfig:
    """Read RPC_URL, CHAIN_ID and EXPLORER_URL from `env_path`."""
    if not env_path.is_file():
        raise DeployError(f"{env_path.name} not found; copy .env.example to {env_path.name} and fill it in")
    values = dotenv_values(env_path)
    rpc_url = (values.get("RPC_URL") or "").strip()
    chain_id = (values.get("CHAIN_ID") or "").strip()
    if not rpc_url:
        raise DeployError(f"RPC_URL is missing in {env_path.name}")
    if not chain_id.isdigit():
        raise DeployError(f"CHAIN_ID in {env_path.name} must be a positive integer")
    explorer_url = (values.get("EXPLORER_URL") or "").strip().rstrip("/")
    return NetworkConfig(env_path, rpc_url, int(chain_id), explorer_url)


def connect(config: NetworkConfig) -> Web3:
    """Connect, refusing a node whose chain differs from the env file's CHAIN_ID."""
    # The RPC URL may embed an API key, so only its host is ever printed.
    host = urlparse(config.rpc_url).hostname or "the RPC endpoint"
    w3 = Web3(Web3.HTTPProvider(config.rpc_url, request_kwargs={"timeout": RPC_TIMEOUT_SECONDS}))
    if not w3.is_connected():
        raise DeployError(f"cannot reach {host}; is the node running?")
    actual = w3.eth.chain_id
    if actual != config.chain_id:
        raise DeployError(f"{host} is chain {actual}, but {config.env_path.name} expects {config.chain_id}")
    return w3


# -------------------------------------------------------------------- deploy


def deploy(w3: Web3, artifact: dict, keystore: Path | None, explorer_url: str) -> Deployment:
    """Send the constructor transaction and wait for the receipt."""
    contract = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
    try:
        if keystore is None:  # the node signs with its own unlocked account
            sender = _node_account(w3)
            _require_balance(w3, sender)
            tx_hash = contract.constructor().transact({"from": sender})
        else:  # sign locally, send raw
            account = _unlock_keystore(keystore)
            _require_balance(w3, account.address)
            tx = contract.constructor().build_transaction(
                {
                    "from": account.address,
                    "nonce": w3.eth.get_transaction_count(account.address, "pending"),
                    "chainId": w3.eth.chain_id,
                }
            )
            tx_hash = w3.eth.send_raw_transaction(account.sign_transaction(tx).raw_transaction)

        print(f"sent deployment tx {tx_hash.to_0x_hex()}")
        if explorer_url:
            print(f"  {explorer_url}/tx/{tx_hash.to_0x_hex()}")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=RECEIPT_TIMEOUT_SECONDS)
    except (Web3Exception, OSError) as exc:
        raise DeployError(f"deployment failed: {exc}") from exc

    if receipt["status"] != 1:
        raise DeployError(f"deployment tx {tx_hash.to_0x_hex()} reverted")
    return Deployment(
        address=receipt["contractAddress"],
        tx_hash=tx_hash.to_0x_hex(),
        block_number=receipt["blockNumber"],
        gas_used=receipt["gasUsed"],
    )


def _node_account(w3: Web3) -> str:
    accounts = w3.eth.accounts
    if not accounts:
        raise DeployError("the node has no unlocked accounts; pass --keystore")
    return accounts[0]


def _require_balance(w3: Web3, address: str) -> None:
    if w3.eth.get_balance(address) == 0:
        raise DeployError(f"deployer {address} has no ETH to pay for gas")


def _unlock_keystore(path: Path) -> LocalAccount:
    """Decrypt an Ethereum JSON keystore; the password prompt does not echo."""
    path = path.expanduser()
    if not path.is_file():
        raise DeployError(f"keystore not found: {path}")
    if path.stat().st_size > MAX_KEYSTORE_BYTES:
        raise DeployError(f"{path.name} is too large to be a keystore")
    keyfile = _read_json(path)
    password = getpass.getpass(f"Password for {path.name}: ")
    try:
        private_key = Account.decrypt(keyfile, password)
    except (ValueError, KeyError, TypeError):
        raise DeployError("wrong password or corrupted keystore") from None
    return Account.from_key(private_key)


# -------------------------------------------------------------------- output


def record_deployment(env_path: Path, deployment: Deployment) -> None:
    """Write CONTRACT_ADDRESS and DEPLOY_BLOCK back into the env file."""
    set_key(env_path, "CONTRACT_ADDRESS", deployment.address, quote_mode="never")
    set_key(env_path, "DEPLOY_BLOCK", str(deployment.block_number), quote_mode="never")


def _print_summary(deployment: Deployment, config: NetworkConfig) -> None:
    print(f"{CONTRACT_NAME} deployed on chain {config.chain_id}")
    print(f"  address   {deployment.address}")
    print(f"  block     {deployment.block_number}")
    print(f"  gas used  {deployment.gas_used}")
    print(f"  tx        {deployment.tx_hash}")
    if config.explorer_url:
        print(f"  explorer  {config.explorer_url}/address/{deployment.address}")
    print(f"CONTRACT_ADDRESS and DEPLOY_BLOCK written to {config.env_path.name}")


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeployError(f"cannot read {path.name}: {exc}") from exc


def _rel(path: Path) -> str:
    return str(path.relative_to(ROOT_DIR))


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=f"Deploy {CONTRACT_NAME} and record its address.")
    parser.add_argument("--network", choices=NETWORKS, default="local", help="reads .env.<network>")
    parser.add_argument("--keystore", type=Path, help="encrypted Ethereum keystore of the deployer")
    parser.add_argument("--export-only", action="store_true", help="build and export the ABI without deploying")
    return parser.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())
