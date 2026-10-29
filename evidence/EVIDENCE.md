# Test and security evidence

Report-ready tables for the testing and security-analysis sections, with the raw logs in `logs/`.

- **Code version**: commit `91fc4cd`, working tree clean. Run `./evidence/collect.sh` again if the code changes before submission, so the logs match the submitted version.
- **Generated**: 25 Oct 2026 (first run 17 Oct; the results are unchanged). Tests, Slither and Bandit ran on Ubuntu 24.04 (x86_64). Gitleaks ran on the repository itself, because it needs the git history and the git-ignored files.

| Tool | Version |
|---|---|
| Python, full suite including GUI tests (under Xvfb) | 3.12.3 |
| Python, version pinned in `environment.yml` (tests without Tk) | 3.11.17 |
| pytest | 9.1.1 |
| cryptography | 50.0.2 (OpenSSL 4.0.3) |
| web3.py / eth-account | 7.16.0 / 0.14.0 |
| Foundry (forge, anvil) | 1.5.1 |
| solc | 0.8.30 |
| Slither | 0.11.6 |
| Bandit | 1.9.4 |
| Gitleaks | 8.28.0 |

## 1. Test results

| Suite | Tests | Passed | Failed | Skipped | Log |
|---|---|---|---|---|---|
| Solidity unit tests (Registration, AccessControl) | 48 | 48 | 0 | 0 | `logs/forge-test.txt` |
| Solidity fuzz tests (1,000 runs each) | 7 | 7 | 0 | 0 | `logs/forge-test.txt` |
| Solidity invariant tests (256 runs × 64 calls each) | 4 | 4 | 0 | 0 | `logs/forge-test.txt` |
| Python unit tests | 385 | 385 | 0 | 0 | `logs/pytest.txt` |
| Python integration tests (fresh Anvil chain) | 54 | 54 | 0 | 0 | `logs/pytest.txt` |
| **Total** | **498** | **498** | **0** | **0** | |

- Each invariant run made 16,384 calls through a handler that predicts every outcome from a reference model of the request state machine. No outcome differed from the model, and no owner-only call by another account succeeded.
- On Python 3.11.17, all 396 tests that do not need Tk also passed (`logs/pytest-py311-no-gui.txt`).

## 2. Contract coverage

`forge coverage --no-match-coverage "test|lib"` (`logs/forge-coverage.txt`):

| File | Lines | Statements | Branches | Functions |
|---|---|---|---|---|
| `src/SecureFileShare.sol` | 100% (75/75) | 100% (93/93) | 100% (21/21) | 100% (16/16) |

## 3. Security test matrix (S1–S16)

Scenarios from DESIGN.md §10.2. Contract-side results quote the revert data from the call traces (`logs/forge-security-reverts.txt`); client-side results are the outcomes the pytest tests assert. In V-check results, P = passed, F = failed, S = skipped because an earlier check failed, and Key is the ECIES unwrap.

| ID | Attack or failure | Stopped by | Observed result | Tests |
|---|---|---|---|---|
| S1 | A user who does not own the file calls `approveAccess` | Contract (`onlyFileOwner`) | Reverts with `NotFileOwner(fileId, caller)`. The client sees the revert during gas estimation and sends nothing (nonce and balance unchanged). Sent anyway with a fixed gas limit, the transaction is mined, reverts with `NotFileOwner`, and the request stays Pending. 1,000 random callers all fail on approve, reject, revoke and deactivate. | `test_strangerCannotApprove`, `testFuzz_nonOwnerCannotManageFile`, `test_revert_is_caught_before_sending`, `test_fixed_gas_limit_mines_the_revert`, `test_unauthorized_approve_is_rejected_before_and_after_broadcast` |
| S2 | Bob approves his own request | Contract | Reverts with `NotFileOwner(fileId, Bob)` | `test_requesterCannotApproveOwnRequest` |
| S3 | Approve twice, or approve a rejected request | Contract (state machine) | Reverts with `InvalidStatus(2)` (Approved) and `InvalidStatus(3)` (Rejected) | `test_cannotApproveTwice`, `test_cannotApproveRejectedRequest` |
| S4 | Owner requests own file; request for an unknown file; requester without registered keys | Contract | `OwnerCannotRequest()`, `FileNotFound(fileId)`, `KeysNotRegistered(user)` | `test_requestAccess_unknownFileReverts`, `test_requestAccess_ownerCannotRequestOwnFile`, `test_requestAccess_requiresRegisteredKeys` |
| S5 | Register the same salt twice | Contract | `FileAlreadyExists(fileId)` | `test_registerFile_rejectsDuplicateSalt` |
| S6 | Storage flips one byte of the ciphertext | Client: V1, and V5 if decryption is forced | `V1:F V2:P V3:P V4:P Key:S V5:S V6:S`, no plaintext. With forced decryption `V5:F` (AES-GCM authentication failed). A flip in the magic, nonce, body or tag is always rejected. | `test_flipped_ciphertext_byte`, `test_forced_decrypt_hits_the_gcm_tag`, `test_any_flipped_byte_is_detected` |
| S7 | Storage changes ptDigest in the manifest without re-signing | Client: V2 and V4 (V6 if forced) | `V1:P V2:F V3:P V4:F`. With forced decryption also `V6:F`; no plaintext | `test_modified_pt_digest`, `test_forced_decrypt_fails_v6`, `test_modified_pt_digest_is_detected` |
| S8 | An attacker forges a manifest and signs it with their own key | Client: V4 (signing key read from the chain) | `V2:F V4:F`; even when the manifest hash matches the chain, `V4:F` | `test_attacker_re_signs_with_own_key`, `test_re_signed_manifest_fails_v4_even_if_hash_matched`, `test_attacker_resigning_fails_with_onchain_key` |
| S9 | Storage replaces the object with an older version of the same file | Client: V1 | `V1:F`, V2–V4 pass | `test_rollback_to_an_older_version` |
| S10 | Mallory copies Bob's wrapped key from the chain and uses her own key | Client: ECIES unwrap | `Key:F` (`KeyUnwrapError`), V5 and V6 skipped | `test_someone_elses_wrapped_key`, `test_other_users_key_fails` |
| S11 | Bob uses the wrapped key of file A for file B | Client: HKDF info and AAD | `Key:F`; changing the chain ID, contract or fileId also makes unwrapping fail | `test_wrapped_key_of_another_file`, `test_wrapped_key_cannot_move_to_another_file` |
| S12 | A rejected or revoked requester asks for the file key | Contract and client | The stored wrapped key is empty (length 0) in both cases; the client refuses with `AccessDeniedError` ("… is Rejected", "… is Revoked") | `test_rejectedAndRevokedRequestersHoldNoWrappedKey`, `TestRejectBranch`, `TestRevokeBranch` |
| S13 | Wrong keystore password | Client: scrypt + AES-GCM keystore | "Wrong password or corrupted keystore"; editing the address, salt, nonce or ciphertext gives the same message | `test_wrong_password`, `test_tampering_looks_like_a_wrong_password` |
| S14 | Malformed or off-curve public key | Contract (encoding) and client (curve check) | `InvalidPublicKey()` for a wrong length or prefix. An off-curve encryption key passes the contract's encoding check, and the owner's client refuses it before wrapping any key. | `test_registerKeys_rejectsWrongLength`, `test_registerKeys_rejectsBadPrefix`, `test_off_curve_encryption_key_is_refused` |
| S15 | Replay a transaction that was already mined | Blockchain (account nonce) | The node rejects the second submission with `nonce too low` | `test_replayed_transaction_is_rejected` |
| S16 | Front-run `registerFile` with the same salt | Contract (fileId = keccak256(owner, salt)) | The attacker gets a different fileId; Alice's registration succeeds and she stays the owner. Holds for 1,000 random attacker and salt pairs. | `test_frontRunWithSameSaltGetsDifferentFileId`, `testFuzz_fileIdIsBoundToSender` |

### Further security tests

| Property | Observed result | Tests |
|---|---|---|
| Manifest copied from another file or chain | V3 fails and names the field (fileId, chainId), while V1 and V2 pass | `test_V3_manifest_of_another_file`, `test_V3_manifest_from_another_chain` |
| Owner signs one plaintext but encrypts another | V1 to V5 pass, V6 fails, no plaintext | `test_V6_owner_signed_a_different_plaintext` |
| Requester's key changes after the owner reviewed it | Approval aborted with `StaleApprovalError`; the request stays Pending | `test_key_change_after_review_aborts` |
| Path traversal through a storage name such as `../../keystore/alice` | Rejected before any path is built | `test_invalid_ct_hash`, `test_invalid_file_id` |
| Path separators or invisible characters in the encrypted file name | Rejected when encrypting and again when decrypting | `test_path_in_header_name`, `test_rejects_invisible_characters`, `test_invisible_character_in_header_name` |
| ECDSA malleability | The high-s twin of a valid signature is rejected; signatures are low-s and deterministic (RFC 6979) | `test_high_s_twin_is_rejected`, `test_signatures_are_low_s`, `test_signing_is_deterministic` |
| Independent check with the Lab 3 formula | The manifest signature verifies with X = u1·G + u2·Q computed in py_ecc | `test_our_manifest_signature_passes_reference_verification` |
| Secrets at rest and in messages | The keystore holds no private key in clear; storage holds no plaintext, file name or label; the DEK appears neither in the wrapped key nor in any verification message | `test_file_contains_no_private_key`, `test_storage_holds_only_ciphertext`, `test_dek_does_not_appear_in_wrapped_key`, `test_details_never_contain_the_dek` |

## 4. Static analysis and secret scanning

| Tool | Scope | Result | Assessment |
|---|---|---|---|
| Slither 0.11.6 | `contracts/src`, 102 detectors | 2 findings, both `timestamp` | False positives. The flagged comparisons are on addresses (`owner == address(0)`, `owner != msg.sender`); Slither treats the whole `FileRecord` as time-dependent because `registeredAt` comes from `block.timestamp`. No decision in the contract depends on time. |
| Bandit 1.9.4 | `app/` and `scripts/`, 7,151 lines | 0 High, 0 Medium, 5 Low; 7 more suppressed with a justified `# nosec` | See the table below |
| Gitleaks 8.28.0 | All 12 commits, and the working tree including the git-ignored `keystore/`, `.env.local`, `storage/` and `.chain/` | 3 findings in each scan, all from the `generic-api-key` rule | False positives, see below. No credential or private key in the history or the working tree: keystores are encrypted and `.env.local` holds no API key. |

Bandit findings:

| Finding | Location | Why it is acceptable |
|---|---|---|
| B101, `assert` used (3) | `app/gui/audit_view.py:143`, `app/gui/owner_view.py:352`, `app/gui/requester_view.py:264` | Type narrowing when filling list rows (`isinstance` on a widget); no security decision depends on them |
| B404, `subprocess` imported | `scripts/deploy.py:19` | Developer script |
| B603, `subprocess` call | `scripts/deploy.py:93` | Fixed argument list (`forge build`), no shell, no user input |
| B404, B603, B607 suppressed (7) | `app/gui/verify_view.py:15` and `383–387` | "Show in folder" runs a fixed command (`open`, `explorer` or `xdg-open`) on a path the app wrote itself |

Gitleaks findings (the same three lines in the history and in the working tree):

| Location | First commit | What the rule matched |
|---|---|---|
| `app/services/owner.py:204` | `62311f7` | the variable name `wrapped_key` followed by a keyword argument in a function call |
| `app/gui/demo_view.py:216` | `b574876` | the same pattern |
| `app/gui/demo_view.py:224` | `5a6c776` | an f-string with a message for the user |

## 5. Gas costs

Gas used by real transactions on Anvil: the table in `contracts/README.md`, re-measured on 17 Oct with differences under 100 gas, which come from the random key bytes in calldata. `logs/forge-gas-report.txt` lists minimum, average and maximum per function over all test calls; the maxima are successful calls and agree with this table, except `registerFile`, whose maximum (188,852) comes from a test with a 128-byte label.

| Transaction | Gas used |
|---|---|
| Deploy `SecureFileShare` | 1,295,598 |
| `registerKeys`, first time / key rotation | 162,342 / 54,444 |
| `registerFile` without a label | 187,279 |
| `requestAccess` | 50,773 |
| `approveAccess` (93-byte wrapped key) | 122,801 |
| `rejectAccess` | 31,554 |
| `revokeAccess` | 41,578 |
| `deactivateFile` | 28,477 |

## 6. Files

| File | Content |
|---|---|
| `logs/environment.txt` | Date, code version, Python and Foundry versions of the run |
| `logs/forge-test.txt` | `forge test -vv`, including fuzz and invariant metrics |
| `logs/forge-security-reverts.txt` | Result and revert lines of `forge test -vvvv`, one block per contract-side test of the S table; `collect.sh` lists the 14 tests. The full traces are left out because they print test-fixture keys that secret scanners report as credentials. |
| `logs/forge-gas-report.txt` | `forge test --gas-report` |
| `logs/forge-coverage.txt` | `forge coverage` summary |
| `logs/pytest.txt` | `pytest -v`, every Python test |
| `logs/pytest-py311-no-gui.txt` | The tests that do not need Tk, on Python 3.11 |
| `logs/bandit.txt`, `logs/slither.txt` | Static analysis |
| `logs/gitleaks-git.*`, `logs/gitleaks-dir.*` | Secret scans of the history and of the working tree, matches redacted |

`./evidence/collect.sh` regenerates every log except `pytest-py311-no-gui.txt`. It needs the `secure-file-share` environment and Foundry, and runs Slither, Bandit and Gitleaks only when they are installed.
