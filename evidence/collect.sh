#!/usr/bin/env bash
# Regenerate the raw logs in evidence/logs/ from the current code.
#
#   conda activate secure-file-share
#   ./evidence/collect.sh
#
# Needs Foundry (forge, anvil) and the secure-file-share environment. Slither, Bandit and
# Gitleaks run when installed and are skipped otherwise. Rerun after the last
# code change so the logs match the final version. Set PYTHON to use another
# interpreter. Takes a few minutes: the invariant tests run three times.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOGS="$ROOT/evidence/logs"
PYTHON="${PYTHON:-python}"
# Contract tests that act out an attack; forge-security-reverts.txt keeps their revert lines.
SECURITY_TESTS='test_(strangerCannotApprove|requesterCannotApproveOwnRequest|cannotApprove(Twice|RejectedRequest)|requestAccess_(unknownFileReverts|ownerCannotRequestOwnFile|requiresRegisteredKeys)|rejectedAndRevokedRequestersHoldNoWrappedKey|registerFile_rejectsDuplicateSalt|frontRunWithSameSaltGetsDifferentFileId|registerKeys_rejects(WrongLength|BadPrefix))|testFuzz_(nonOwnerCannotManageFile|fileIdIsBoundToSender)'
cd "$ROOT"
rm -rf "$LOGS"
mkdir -p "$LOGS"

have() { command -v "$1" > /dev/null 2>&1; }

run() {  # run <log file> <command...>: keep stdout and stderr, show the exit code
    local log="$1"
    shift
    printf '%-30s' "$log"
    "$@" > "$LOGS/$log" 2>&1
    echo "exit $?"
}

{
    echo "date      $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if git rev-parse --git-dir > /dev/null 2>&1; then
        # Only code counts: evidence/ itself is written by this script.
        dirty=$(git status --porcelain -- . ':(exclude)evidence' | grep -q . && echo " + uncommitted changes")
        echo "commit    $(git rev-parse --short HEAD)${dirty}"
    else
        echo "commit    (not a git repository)"
    fi
    echo "system    $(uname -sm)"
    echo "python    $("$PYTHON" --version 2>&1)"
    "$PYTHON" -c "import importlib.metadata as m; print('packages ', ', '.join(p + ' ' + m.version(p) for p in ('cryptography', 'web3', 'eth-account', 'pytest')))"
    echo "forge     $(forge --version | head -1)"
} > "$LOGS/environment.txt" 2>&1

# Secret scans first, while evidence/logs/ is still empty.
if have gitleaks; then
    run gitleaks-git.txt gitleaks git . --redact --no-banner --no-color -v \
        --report-format json --report-path "$LOGS/gitleaks-git.json"
    run gitleaks-dir.txt gitleaks dir . --redact --no-banner --no-color -v \
        --report-format json --report-path "$LOGS/gitleaks-dir.json"
else
    echo "gitleaks not installed, skipped"
fi

(cd contracts && forge build > /dev/null 2>&1)
run forge-test.txt sh -c 'cd contracts && forge test -vv'
# Only the result and revert lines: the full traces print test-fixture keys that
# secret scanners report as credentials.
run forge-security-reverts.txt bash -c 'set -o pipefail; cd contracts &&
    forge test --mt "$1" -vvvv | grep -E "^\[(PASS|FAIL)\]|Revert\]"' _ "$SECURITY_TESTS"
run forge-gas-report.txt sh -c 'cd contracts && forge test --gas-report'
run forge-coverage.txt sh -c 'cd contracts && forge coverage --no-match-coverage "test|lib" --report summary'
run pytest.txt "$PYTHON" -m pytest -v -p no:cacheprovider

if have bandit; then
    run bandit.txt bandit -r app scripts
else
    echo "bandit not installed, skipped"
fi
if have slither; then  # last: it runs forge clean
    # Slither matches the filter against absolute paths, so "lib|test" alone would also
    # hide src/ whenever the project sits under a folder whose name contains "test".
    run slither.txt sh -c 'cd contracts && slither . --filter-paths "contracts/(lib|test)/"'
else
    echo "slither not installed, skipped"
fi
echo "Logs written to evidence/logs/. Gitleaks, Bandit and Slither exit with 1 (Slither 255) when they report anything."
