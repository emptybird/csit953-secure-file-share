#!/usr/bin/env bash
# Start a local Anvil chain (chainId 31337). State is saved to .chain/state.json
# on exit and reloaded on the next start, so deployed contracts survive restarts.
# Delete .chain/ for a fresh chain. Extra arguments are passed to anvil.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT_DIR/.chain"
exec anvil --chain-id 31337 --state "$ROOT_DIR/.chain/state.json" "$@"
