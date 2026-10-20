# Secure File Share

English | [中文](README.zh.md)

CSIT953 Assignment 2: a file storage and sharing system that combines client-side cryptography with an Ethereum smart contract.

- Files are encrypted on the owner's computer with AES-256-GCM, using a fresh 256-bit key per file, and signed with ECDSA (secp256k1). Only ciphertext and a signed manifest go to storage, which is treated as untrusted.
- The `SecureFileShare` contract registers public keys and files, runs the request → approve / reject → revoke workflow, lets only a file's owner decide, and records every step as an event.
- On approval the owner encrypts the file key to the requester's registered encryption key (ECIES: ECDH + HKDF-SHA256 + AES-256-GCM). The 93-byte wrapped key is stored on-chain, and only the requester can open it.
- Before anything is decrypted, the requester checks the download against the on-chain record (V1–V6 below).
- A Tkinter desktop app covers both the owner and the requester workflows. It never displays a private key or a file key, only fingerprints.

Design decisions, threat model and limitations: [DESIGN.md](DESIGN.md). Contract interface, gas costs and Slither results: [contracts/README.md](contracts/README.md). Chinese versions: [DESIGN.zh.md](DESIGN.zh.md), [contracts/README.zh.md](contracts/README.zh.md).

## Requirements

| Tool | Used for |
|---|---|
| conda (Miniforge or Miniconda) | the `953-a2` environment from `environment.yml`: Python 3.11, Tk ≥ 8.6.13, cryptography, web3, eth-account, python-dotenv, pytest, py_ecc, bandit |
| [Foundry](https://book.getfoundry.sh/getting-started/installation) | `anvil` (local chain) and `forge` (build and contract tests) |

`forge-std` is vendored in `contracts/lib/`, so no `forge install` is needed. Foundry on Windows needs Git Bash or WSL; without Foundry, `scripts/deploy.py` deploys the committed artifact in `app/chain/abi/`.

## Quick start on a local chain

Run everything from the project root.

```sh
conda env create -f environment.yml
conda activate 953-a2
cp .env.example .env.local

./scripts/start_chain.sh                     # terminal 1: Anvil on 127.0.0.1:8545, chain 31337
python scripts/deploy.py --network local     # terminal 2: build, export the ABI, deploy, write CONTRACT_ADDRESS
python -m app.gui                            # the desktop app
```

`start_chain.sh` saves the chain to `.chain/state.json` every 5 seconds and on Ctrl-C, so the contract and registered files survive a restart. For a fresh start, delete `.chain/` and `storage/`, then deploy again.

## Two-user walkthrough

Open one window per user. All windows on this computer share `storage/`.

```sh
python -m app.gui --network local --keystore alice
python -m app.gui --network local --keystore bob
```

1. **Create a keystore**: on the login page choose *Create a new keystore*. It generates three keys (transactions, file signing, file encryption) and saves them in `keystore/<name>.json`, encrypted with your password (scrypt + AES-256-GCM, at least 8 characters).
2. **Fund and register**: on the local chain click *Add 100 test ETH* in the banner, then *Register keys*. This transaction binds the two public keys to the account address.
3. **Alice protects a file**: *Protect a file* → choose a file and an optional public label. The page shows each step (encrypt, sign, upload, register) with the transaction hash, block and gas. Copy the file ID.
4. **Bob requests access**: *Browse files* → select the file → *Request access*. The status updates on its own.
5. **Alice decides**: *My files* → select the file. *Approve* shows the fingerprint of Bob's encryption key; compare it with the fingerprint Bob sees next to his request. *Reject*, *Revoke access* and *Deactivate file* are on the same page.
6. **Bob retrieves and verifies**: *Retrieve and verify* reads the authorization (the wrapped key), runs V1–V4, unwraps the file key, decrypts, and runs V5–V6. *Save decrypted file* is enabled only when every check passed.
7. **Audit**: *Activity* lists every contract event; *Export CSV* saves them as evidence.

| Check | Compares | Detects |
|---|---|---|
| V1 | SHA-256 of the downloaded object with the on-chain ctHash | modified, replaced or deleted ciphertext |
| V2 | SHA-256 of the manifest with the on-chain manifestHash | modified manifest |
| V3 | chain, contract, fileId, owner and ctHash in the manifest with the on-chain record | a manifest taken from another file or chain |
| V4 | the ECDSA signature with the owner's signing key **as registered on-chain** | forged or re-signed manifest |
| Key | ECIES unwrap with the requester's encryption key | a wrapped key made for another file or person |
| V5 | the AES-256-GCM tag | modified ciphertext, wrong file context |
| V6 | SHA-256 of the decrypted data with the digest the owner signed | content other than what the owner signed |

### Security demo

`SFS_DEMO=1 python -m app.gui` (or `--demo`) adds a *Security demo* page:

- **Tamper with storage**: flip one bit of the ciphertext, change the digest in the manifest, or delete the ciphertext, then open *Retrieve and verify* to see which check fails. *Restore the originals* puts the files back. In demo mode the verify page also offers to decrypt despite failed checks, which shows the GCM tag check (V5) catching the change.
- **Approve another owner's file**: calls `approveAccess` from the current account on a file it does not own. Gas estimation stops the call before it is sent; with *Broadcast anyway* it is sent with a fixed gas limit, so the reverted transaction is mined and visible on-chain.

## Tests

```sh
(cd contracts && forge test)    # contract: unit, fuzz (1,000 runs) and invariant tests
pytest                          # Python: unit and integration tests
```

The integration tests start their own Anvil on a free port and deploy a fresh contract, so they never touch `.chain/` or `.env.local`. They are skipped when `anvil` is not on `PATH`; set `ANVIL_BIN` to its location. Tests that need a display are skipped without one.

Optional checks:

```sh
(cd contracts && forge coverage --no-match-coverage "test|lib")
(cd contracts && slither . --filter-paths "contracts/(lib|test)/")
bandit -r app scripts
```

### Security test matrix

Every scenario of DESIGN.md §10.2 has an automated test. Solidity tests are in `contracts/test/`, Python tests in `tests/unit/` and `tests/integration/`. Run one scenario with `forge test --mt S1` or `pytest -k S6`.

| ID | Scenario | Expected result | Tests |
|---|---|---|---|
| S1 | Another user calls `approveAccess` on Alice's file | revert `NotFileOwner` | `AccessControl.t.sol::test_S1_strangerCannotApprove`, `Fuzz.t.sol::testFuzz_S1_nonOwnerCannotManageFile`, `test_chain_client.py::test_S1_revert_is_caught_before_sending`, `test_gui_demo.py::test_unauthorized_approve_is_rejected_before_and_after_broadcast` |
| S2 | Bob approves his own request | revert `NotFileOwner` | `AccessControl.t.sol::test_S2_requesterCannotApproveOwnRequest` |
| S3 | Approve twice, or approve a rejected request | revert `InvalidStatus` | `AccessControl.t.sol::test_S3_cannotApproveTwice`, `test_S3_cannotApproveRejectedRequest` |
| S4 | Owner requests own file; unknown file; requester without keys | revert `OwnerCannotRequest`, `FileNotFound`, `KeysNotRegistered` | `AccessControl.t.sol::test_S4_*` |
| S5 | Register the same salt twice | revert `FileAlreadyExists` | `Registration.t.sol::test_S5_registerFile_rejectsDuplicateSalt` |
| S6 | Flip a byte of the stored ciphertext | V1 fails; forced decryption fails V5 | `test_verification.py::test_S6_*`, `test_aead.py::test_S6_any_flipped_byte_is_detected` |
| S7 | Change ptDigest in the stored manifest | V2 and V4 fail; forced decryption fails V6 | `test_verification.py::test_S7_*`, `test_signing.py::test_S7_modified_pt_digest_is_detected` |
| S8 | Attacker re-signs a forged manifest with their own key | V4 fails, because the key comes from the chain | `test_verification.py::test_S8_*`, `test_signing.py::test_S8_attacker_resigning_fails_with_onchain_key` |
| S9 | Roll the object back to an older version | V1 fails | `test_verification.py::test_S9_rollback_to_an_older_version` |
| S10 | Mallory opens Bob's wrapped key with her own key | unwrap fails | `test_verification.py::test_S10_someone_elses_wrapped_key`, `test_ecies.py::test_S10_other_users_key_fails` |
| S11 | Use file A's wrapped key for file B | unwrap fails (HKDF info and AAD differ) | `test_verification.py::test_S11_wrapped_key_of_another_file`, `test_ecies.py::test_S11_wrapped_key_cannot_move_to_another_file` |
| S12 | A rejected or revoked requester asks for the key | no wrapped key on-chain; the client refuses | `AccessControl.t.sol::test_S12_rejectedAndRevokedRequestersHoldNoWrappedKey`, `test_workflows.py::TestRejectBranch`, `TestRevokeBranch` |
| S13 | Wrong keystore password | not opened; same message as a damaged file | `test_keystore.py::test_S13_wrong_password`, `test_tampering_looks_like_a_wrong_password` |
| S14 | Register a malformed or off-curve public key | the contract reverts; the owner's client refuses to wrap | `Registration.t.sol::test_S14_*`, `test_workflows.py::test_S14_off_curve_encryption_key_is_refused` |
| S15 | Replay a mined transaction | the node rejects the used nonce | `test_chain_client.py::test_S15_replayed_transaction_is_rejected` |
| S16 | Front-run a registration with the same salt | different fileId; the owner is unaffected | `Registration.t.sol::test_S16_frontRunWithSameSaltGetsDifferentFileId`, `Fuzz.t.sol::testFuzz_S16_fileIdIsBoundToSender` |

## Project layout

```
app/
  config.py      network settings from .env.<network>
  crypto/        AES-256-GCM files, ECDSA manifests, ECIES key wrapping, keystore, canonical encodings
  storage/       a local directory that simulates untrusted object storage
  chain/         web3.py client, readable revert messages, event log and CSV export
  services/      owner and requester workflows and the V1–V6 checks, without GUI code
  gui/           the Tkinter app (python -m app.gui)
contracts/       Foundry project: SecureFileShare.sol and its tests
scripts/         start_chain.sh (Anvil) and deploy.py (build, export the ABI, deploy)
tests/           unit/ and integration/ (pytest)
evidence/        EVIDENCE.md (test and scan results for the report), logs/, collect.sh
```

Created at run time and git-ignored: `keystore/` (encrypted keys), `storage/` (ciphertext objects and signed manifests), `.chain/` (Anvil state), `.env.local` and `.env.sepolia`.

## Configuration

Each network has a `.env.<name>` file, copied from `.env.example`. The login page lists every such file it finds.

| Key | Meaning |
|---|---|
| `RPC_URL` | node endpoint; it may contain an API key, so the app only shows its host |
| `CHAIN_ID` | checked against the node on connect |
| `CONTRACT_ADDRESS`, `DEPLOY_BLOCK` | written by `scripts/deploy.py` |
| `EXPLORER_URL` | optional, e.g. `https://sepolia.etherscan.io`; makes transaction hashes open in the explorer |
| `STORAGE_DIR` | optional, default `storage/`; windows that should see the same files must use the same folder |

### Sepolia (optional)

The brief allows a local chain. Sepolia adds public transaction records that anyone can check. Deployment with an encrypted deployer keystore and source verification are described in [contracts/README.md](contracts/README.md#sepolia). Every user account needs Sepolia ETH for gas.

## Known limitations

- Revocation deletes the wrapped key from contract storage, but the approval transaction stays on-chain, and a requester who already decrypted keeps the plaintext. Cutting off future access needs a new file key, i.e. protecting the file again.
- Replacing the on-chain keys breaks older files: V4 checks against the owner's current signing key, and keys wrapped for the old encryption key need the old keystore.
- Owners, requesters, timestamps and optional public labels are visible to everyone on-chain.
- The client trusts its RPC node. Storage can delete files; the client detects this but cannot prevent it.
- Keys and plaintext stay in Python memory while the app runs, and files are read whole (up to about 50 MB).

## Troubleshooting

| Symptom | Fix |
|---|---|
| Clicks are ignored or the window draws incorrectly on macOS | run from the `953-a2` conda environment (Tk ≥ 8.6.13); the app warns about older Tk versions |
| "No contract at … deploy it first" | the chain was reset; run `python scripts/deploy.py --network local` again |
| "Cannot reach 127.0.0.1 …" | start `./scripts/start_chain.sh` |
| "Not enough ETH in this account to pay for gas" | *Add 100 test ETH* on the local chain, or fund the address on Sepolia |
| "The on-chain keys for this address differ from this keystore" | the address registered keys from another keystore; use that keystore, or replace the keys on the Account page (files signed with the old key then fail V4) |
| Integration tests are skipped | install Foundry or set `ANVIL_BIN` |

## Packaging

`git archive -o secure-file-share.zip HEAD` packs the committed files only, so keystores, `.env` files, local storage and chain state stay out of the archive.
