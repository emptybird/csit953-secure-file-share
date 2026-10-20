#!/usr/bin/env bash
# Start a local Anvil chain (chainId 31337). State is saved to .chain/state.json
# every STATE_INTERVAL seconds and on Ctrl-C, and reloaded on the next start, so
# deployed contracts and registered files survive restarts. Anvil does not save
# when the terminal window is closed (SIGHUP) or the process is killed; the
# periodic save limits that loss to the last few seconds.
# Delete .chain/ for a fresh chain. Extra arguments are passed to anvil.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
STATE_INTERVAL=5
mkdir -p "$ROOT_DIR/.chain"
exec anvil --chain-id 31337 --state "$ROOT_DIR/.chain/state.json" --state-interval "$STATE_INTERVAL" "$@"
