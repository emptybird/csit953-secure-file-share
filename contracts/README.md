# contracts: SecureFileShare

> Chinese version: [README.zh.md](README.zh.md).

The contract from section 5 of [DESIGN.md](../DESIGN.md). A Foundry project: solc 0.8.30, optimizer with 200 runs.

```
src/SecureFileShare.sol                  the contract
test/utils/BaseTest.sol                  shared fixture: Alice owns the files, Bob and Carol request, Mallory has no rights, Nobody has no registered keys
test/Registration.t.sol                  registerKeys, registerFile, view functions
test/AccessControl.t.sol                 request state machine, owner checks, deactivated files
test/Fuzz.t.sol                          property tests with random callers and random byte strings
test/invariant/                          handler with a reference model, and 4 invariants
lib/forge-std                            test library v1.17.0, committed, so no install is needed after cloning
```

## Common commands (run in `contracts/`)

```sh
forge build
forge test                       # 59 tests: unit, fuzz (1000 runs each) and invariant (256 runs × 64 calls)
forge test --mt S1 -vvv          # only the tests whose name contains S1
forge test --gas-report
forge coverage --no-match-coverage "test|lib"   # currently 100% of lines, statements, branches and functions
slither . --filter-paths "contracts/(lib|test)/"
```

`S1` to `S16` in test names refer to the security test matrix in DESIGN.md 10.2. The contract tests cover S1–S5, S12, S14 (length and prefix) and S16. S15 relies on the chain's nonce check, so the pytest integration tests cover it. The other scenarios are checked by the client.

The invariant handler keeps a reference state machine. Before each call it predicts whether the call should succeed or revert, then compares that with what the contract did. The 4 invariants:

- no owner-only call by a non-owner ever succeeded;
- every call had the result the model predicted;
- the on-chain state matches the model;
- `wrappedKey` is non-empty ⇔ `status == Approved`.

On a copy of the contract we planted 5 bugs, and the invariant tests caught each one: `onlyFileOwner` removed from approve; `delete req.wrappedKey` removed from revoke; reject allowed straight from Approved; approve not checking `active`; a new request allowed while Approved. Any of them works as a live demo.

## Deployment

Run these from the repository root.

### Local chain

```sh
./scripts/start_chain.sh                        # in another terminal; the state is kept in .chain/state.json
cp .env.example .env.local
conda activate secure-file-share
python scripts/deploy.py --network local
```

`deploy.py` runs `forge build`, exports the ABI and bytecode to `app/chain/abi/SecureFileShare.json`, checks that the RPC's chainId matches `.env.local`, deploys, and writes `CONTRACT_ADDRESS` and `DEPLOY_BLOCK` back to `.env.local`. On the local chain it sends from Anvil's development account 0, which the node unlocks itself, so no private key appears in code or config. Team members without Foundry (Windows) deploy from the artifact already exported in the repository. `--export-only` exports without deploying.

### Sepolia

```sh
cast wallet import deployer --interactive       # stores the private key, encrypted, in ~/.foundry/keystores/deployer
cp .env.example .env.sepolia                    # then switch to the three Sepolia lines commented out in the file
python scripts/deploy.py --network sepolia --keystore ~/.foundry/keystores/deployer
```

The password is read with getpass and not echoed. To verify the source on Etherscan (the API key goes in `.env.sepolia`, never on the command line):

```sh
cd contracts
set -a; source ../.env.sepolia; set +a
forge verify-contract "$CONTRACT_ADDRESS" src/SecureFileShare.sol:SecureFileShare --chain sepolia --watch
```

## Gas (measured on Anvil, including the 21,000 base cost)

| Operation | gasUsed |
|---|---|
| Deployment | 1,295,598 |
| registerKeys (first time / replacing keys) | 162,342 / 54,444 |
| registerFile | 187,279 |
| requestAccess | 50,773 |
| approveAccess | 122,801 |
| rejectAccess | 31,554 |
| revokeAccess | 41,578 |
| deactivateFile | 28,477 |

The Sepolia evidence in DESIGN.md 10.4 (E1–E6, including 3 transactions that fail on purpose) uses about 2.6M gas in total. Multiply by the current gas price to get the test ETH you need.

## Slither

`slither . --filter-paths "contracts/(lib|test)/"`: 102 detectors, 2 results, both `timestamp` false positives. Slither matches the filter against absolute paths, so the shorter `"lib|test"` would also hide `src/` whenever the project sits in a folder whose name contains "test".

The flagged lines are `owner == address(0)` and `owner != msg.sender` in `getFile` and `_requireFileOwner`, which compare addresses. Slither marks the whole `FileRecord` as timestamp-dependent because `registeredAt`, in the same struct, comes from `block.timestamp`. The contract makes no decision based on time.

## Differences from DESIGN.md 5.2 / 5.3

1. Two more errors: `InvalidHash` (ctHash or manifestHash is zero) and `LabelTooLong` (publicLabel longer than 128 bytes). They implement "every input is checked for length and non-zero values" from 5.6.
2. `registerKeys` rejects a sigPubKey equal to the encPubKey, so the contract itself enforces the separate key roles of 4.1.
3. `approveAccess` requires the file to be active: after deactivation nobody new can be approved, but reject and revoke still work.
4. A new view, `computeFileId(owner, salt)`. The client needs the fileId for the AAD before it encrypts; calling this view guarantees the same formula as the contract.
5. The views return structs: `getUserKeys` → `(sigPubKey, encPubKey)`, `getFile` → `FileRecord`, `getRequest` → `Request`. web3.py returns them as tuples in field order. `getFile` reverts with `FileNotFound` for an unknown file; `getRequest` returns `Status.None` (0) for a pair that never requested.
6. `app/chain/abi/SecureFileShare.json` has the format `{contractName, compiler, abi, bytecode}`; the client reads `["abi"]`.

## Notes for the client

- `Status` enum: 0 None, 1 Pending, 2 Approved, 3 Rejected, 4 Revoked.
- In web3.py a revert raises `ContractCustomError`. The first 4 bytes of `exc.data` are the error selector; the error entries in the ABI turn it back into a name.
- After `sigPubKey` is replaced, old manifests still need the old public key, but V4 reads the new one from the chain. One fix is to find the key that was active when the file was registered in the `KeysRegistered` events; another is a rule that signing keys are never replaced. The same goes for `encPubKey`: if it is replaced after an approval, the old wrappedKey only opens with the old private key. The client does neither. Replacing keys needs an explicit confirmation ("Replace on-chain keys" on the Account page) that warns about both effects, and DESIGN.md section 11 lists this as a limitation.
