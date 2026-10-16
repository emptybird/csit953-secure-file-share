from __future__ import annotations

from pathlib import Path

import pytest

from app.config import ConfigError, NetworkConfig, available_networks, load_config

CONTRACT = "0x5FbDB2315678afecb367f032d93F642f64180aa3"


def _write_env(root: Path, network: str, **values: str) -> None:
    base = {
        "RPC_URL": "http://127.0.0.1:8545",
        "CHAIN_ID": "31337",
        "CONTRACT_ADDRESS": CONTRACT,
        "DEPLOY_BLOCK": "1",
        "EXPLORER_URL": "",
    }
    lines = (f"{key}={value}" for key, value in {**base, **values}.items())
    (root / f".env.{network}").write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestLoad:
    def test_local(self, tmp_path: Path) -> None:
        _write_env(tmp_path, "local")
        config = load_config("local", root=tmp_path)
        assert config.network == NetworkConfig(
            name="local",
            rpc_url="http://127.0.0.1:8545",
            chain_id=31337,
            contract_address=CONTRACT,
            deploy_block=1,
            explorer_url="",
        )
        assert config.storage_dir == tmp_path / "storage"
        assert config.keystore_dir == tmp_path / "keystore"

    def test_contract_address_is_checksummed(self, tmp_path: Path) -> None:
        _write_env(tmp_path, "local", CONTRACT_ADDRESS=CONTRACT.lower())
        assert load_config("local", root=tmp_path).network.contract_address == CONTRACT

    def test_storage_dir_relative_and_absolute(self, tmp_path: Path) -> None:
        _write_env(tmp_path, "local", STORAGE_DIR="shared/store")
        assert load_config("local", root=tmp_path).storage_dir == tmp_path / "shared" / "store"
        _write_env(tmp_path, "local", STORAGE_DIR=str(tmp_path / "abs"))
        assert load_config("local", root=tmp_path).storage_dir == tmp_path / "abs"

    def test_deploy_block_defaults_to_zero(self, tmp_path: Path) -> None:
        _write_env(tmp_path, "local", DEPLOY_BLOCK="")
        assert load_config("local", root=tmp_path).network.deploy_block == 0

    def test_explorer_links(self, tmp_path: Path) -> None:
        _write_env(tmp_path, "sepolia", CHAIN_ID="11155111", EXPLORER_URL="https://sepolia.etherscan.io/")
        network = load_config("sepolia", root=tmp_path).network
        assert network.tx_url("0xab") == "https://sepolia.etherscan.io/tx/0xab"
        assert network.address_url(CONTRACT) == f"https://sepolia.etherscan.io/address/{CONTRACT}"

    def test_no_explorer_means_no_links(self, tmp_path: Path) -> None:
        _write_env(tmp_path, "local")
        assert load_config("local", root=tmp_path).network.tx_url("0xab") == ""

    def test_rpc_host_hides_the_api_key(self, tmp_path: Path) -> None:
        _write_env(tmp_path, "sepolia", RPC_URL="https://eth-sepolia.g.alchemy.com/v2/SECRETKEY")
        assert load_config("sepolia", root=tmp_path).network.rpc_host == "eth-sepolia.g.alchemy.com"


class TestInvalid:
    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match=r"\.env\.local not found"):
            load_config("local", root=tmp_path)

    @pytest.mark.parametrize("name", ["../local", "LOCAL", "example", "", "a" * 33])
    def test_bad_network_name(self, tmp_path: Path, name: str) -> None:
        with pytest.raises(ConfigError):
            load_config(name, root=tmp_path)

    def test_contract_not_deployed_yet(self, tmp_path: Path) -> None:
        _write_env(tmp_path, "local", CONTRACT_ADDRESS="")
        with pytest.raises(ConfigError, match="deploy"):
            load_config("local", root=tmp_path)

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("CONTRACT_ADDRESS", "0x1234"),
            ("CHAIN_ID", "abc"),
            ("CHAIN_ID", "0"),
            ("CHAIN_ID", "²"),
            ("CHAIN_ID", ""),
            ("DEPLOY_BLOCK", "-1"),
            ("RPC_URL", ""),
            ("RPC_URL", "ftp://example.com"),
            ("RPC_URL", "127.0.0.1:8545"),
            ("EXPLORER_URL", "javascript:alert(1)"),
        ],
    )
    def test_bad_value_names_the_key(self, tmp_path: Path, key: str, value: str) -> None:
        _write_env(tmp_path, "local", **{key: value})
        with pytest.raises(ConfigError, match=key):
            load_config("local", root=tmp_path)


def test_available_networks(tmp_path: Path) -> None:
    _write_env(tmp_path, "sepolia")
    _write_env(tmp_path, "local")
    (tmp_path / ".env.example").write_text("RPC_URL=\n", encoding="utf-8")
    (tmp_path / ".env.Bad Name").write_text("", encoding="utf-8")
    assert available_networks(tmp_path) == ["local", "sepolia"]
