# CSIT953 Assignment 2: Secure File Sharing System, Technical Design

> Due 11:30 pm, Wed 28 Oct 2026 · group work (up to 5 people) · 30 marks (implementation and report 26, demo 4)
> Sources: `task_requirement.md`, Labs 1–4 and the Week 2–11 slides. "W3" means the Week 3 lecture. The "Course" column names the source, so the report can cite it.
> Chinese version: [DESIGN.zh.md](DESIGN.zh.md) (as of 18 Oct 2026).

---

## 0. Summary

**The plan in brief**
- The client encrypts each file with AES-256-GCM and signs it with ECDSA (secp256k1). Only ciphertext goes to off-chain storage, which is untrusted.
- A smart contract registers files and runs the workflow request → approve or reject → revoke. Only the file's owner can decide.
- On approval, the owner encrypts the file key (DEK) for the requester with ECIES and stores the result in the contract.

| Layer | Choice | Why | Course |
|---|---|---|---|
| Language | Python 3.11+ | Labs 1, 3 and 4 use Python; the team knows it | Labs 1/3/4 |
| Contract | Solidity ^0.8.24 | Used in Lab 2; 0.8 checks for overflow | Lab 2, W3 |
| Blockchain | **Anvil** local chain for development and automated tests; the final version on **Sepolia** for evidence and the demo, with the local chain as backup (see 5.1) | Local chain: instant blocks, reproducible. Sepolia: public Etherscan records the marker can check | Labs 1/2 |
| Contract build and tests | Foundry (`forge build`, `forge test`, including fuzzing) | `vm.prank` and `vm.expectRevert` make tests of unauthorized calls easy | W10 fuzzing |
| Chain access | web3.py 7.x + eth-account | Same as Lab 1 | Lab 1 |
| Crypto library | **pyca/cryptography** (OpenSSL) | Has AES-GCM, HKDF, ECDSA and ECDH on secp256k1, and scrypt; built on the widely audited OpenSSL | Replaces py_ecc from the labs |
| Off-chain storage | A local folder that simulates untrusted cloud object storage, addressed by the SHA-256 of the ciphertext; an HTTP storage service could be added for a two-computer demo (see 2.2) | Allowed by the brief; content addressing gives an integrity anchor for free | W4 object storage |
| GUI | Tkinter desktop app (quiz3's threading pattern; compatibility in 8.1) | No extra dependencies; the team has used it | Lab 3 GUI |
| Testing | pytest, forge test, Slither, Bandit, Gitleaks | Functions, unauthorized calls, static analysis, secret scanning | W9, W10 |

**Six key decisions** (the report must explain why for each one):

1. **Envelope encryption**: a random DEK per file, wrapped separately for each recipient (per-recipient wrapping). (W4 envelope encryption)
2. **AEAD, not CTR**: Lab 4's CTR mode starts every message from the same counter, so the keystream repeats and nothing protects integrity. We use AES-256-GCM with a random nonce and AAD that binds the context.
3. **Three keys per user, one job each**: a transaction key, a signing key and an encryption key. The key that signs files never signs transactions.
4. **Public keys registered on-chain**: the holder of an address writes the address → public key binding with their own transaction. This solves public key substitution (W7) and the DH man-in-the-middle problem (W6).
5. **ECIES for key sharing**: non-interactive (the requester can be offline), a fresh ephemeral key for every wrap, and HKDF bound to the fileId and the requester, so a wrapped key cannot be reused elsewhere.
6. **Minimal on-chain data**: only a random fileId, hashes, public keys, wrapped keys (ciphertext) and request states. No file names, plaintext hashes or DEKs.

---

## 1. Marking criteria → design → evidence

| Criterion | Marks | Our approach | Evidence for the report and demo |
|---|---|---|---|
| File Encryption & Decryption | 4 | AES-256-GCM, one DEK per file, random 96-bit nonce, AAD binds chainId, contract, fileId and owner; encrypt before upload | Screenshot of storage holding only ciphertext; GCM error after flipping one byte |
| Digital Signatures | 2 | ECDSA-secp256k1-SHA256 over a manifest (ciphertext hash + salted plaintext digest); the verification key is read from the chain | Valid signature ✓; changed manifest, other key or changed ciphertext ✗ |
| Blockchain & Smart Contract | 6 | `SecureFileShare`: key registry, file registry, request state machine, owner-only decisions, revocation, audit events | forge test report, Sepolia transaction table and Etherscan screenshots, event log, Slither results |
| Secure Key Sharing | 3 | ECIES (secp256k1, HKDF-SHA256, AES-256-GCM); the 93-byte wrapped key is stored on-chain | The requester unwraps the key; a third party's key fails; a moved wrapped key fails |
| GUI | 3 | Owner and requester pages plus an Activity page; ✓/✗ feedback and a receipt for every step | 4–6 chosen screenshots |
| Security & Robustness | 4 | Threat model, 16 security tests, static analysis, limitations | Security test matrix (section 10) |
| Written Report | 4 | At most 20 pages, page budget in section 13 | n/a |
| Demonstration | 4 | Everyone can walk through the whole flow and make a small change live | Checklist in section 14 |

---

## 2. System architecture

```
┌───────────────────────── Client (trusted) ────────────────────────┐
│  Tkinter GUI  ──►  services (owner / requester workflows)         │
│                     │              │                │             │
│                  crypto/        storage/         chain/           │
│        AES-GCM · ECDSA ·     object store     web3.py contract    │
│        ECIES · keystore      client           client              │
│  keystore/<alias>.json: three private keys, scrypt + AES-GCM      │
└──────────────┬───────────────────────────────┬────────────────────┘
               │ ciphertext + signed manifest  │ signed transactions, events
               ▼                               ▼
   ┌─────────────────────────┐     ┌──────────────────────────────────┐
   │ Off-chain storage       │     │ Blockchain: Anvil / Sepolia      │
   │ (untrusted)             │     │ SecureFileShare contract         │
   │ objects/<ctHash>.bin    │     │ keys · file records · requests   │
   │ manifests/<fileId>.json │     │ wrapped keys · audit events      │
   └─────────────────────────┘     └──────────────────────────────────┘
```

- **Trust boundary**: only the user's own computer is trusted. Storage, the network and other users are not. The blockchain is trusted for integrity and ordering, not for secrecy.
- **Layers**: `services` does not depend on the GUI, so tests and scripts call it directly. The GUI only displays results and manages threads.
- **Any user can be both owner and requester.** For the demo, open two GUI windows with Alice's and Bob's keystores (as in quiz3).

### 2.1 What goes on-chain

| Data | Where | Why |
|---|---|---|
| Signing and encryption public keys (33-byte compressed each) | On-chain | Authoritative binding of address to keys |
| fileId (random 32 bytes), owner address, registration time | On-chain | Needed by the state machine and the audit trail |
| ctHash = SHA-256(ciphertext object), manifestHash | On-chain | Integrity anchors against tampering and rollback |
| Request status, timestamps | On-chain | Audit and access control |
| wrappedKey (the DEK encrypted with ECIES) | On-chain | Only the intended requester can open it, so it is safe in public |
| Optional publicLabel (emitted in an event only) | On-chain event | Helps requesters recognize a file; the GUI says it is public and leaves it empty by default |
| Plaintext, DEK, private keys | **Never on-chain** | n/a |
| File name, MIME type, plaintext digest | Off-chain; the file name is inside the ciphertext | Avoids metadata leaks and dictionary attacks on plaintext hashes |
| Reason for a request | Not collected | Data minimization |

**State this in the report**: Solidity `private` variables, all calldata and all events can be read by anyone, and nothing on-chain can be deleted. Wrapped keys stay secret only because of ECIES. The contract's `msg.sender` checks control authorization, not confidentiality.

### 2.2 Off-chain storage

**Why we need it**: files cannot go on-chain, so we need off-chain storage, but not a real file system or cloud service. Section 2.1 of the brief allows "local storage, simulated cloud storage", so a local folder is enough. The threat model treats it as untrusted cloud storage (attacker A1).

**Default: a local folder that simulates cloud object storage**

```
storage/                          # STORAGE_DIR; every GUI window uses the same folder
├── objects/ab/ab3f…e9.bin        # ciphertext object, named SHA-256(content), grouped by its first 2 hex digits
└── manifests/0x7c…41.json        # signed manifest, named by fileId
```

```python
class ObjectStore(Protocol):                       # app/storage/object_store.py
    def put_object(self, data: bytes) -> str: ...  # returns ctHash (hex)
    def get_object(self, ct_hash: str) -> bytes: ...
    def put_manifest(self, file_id: str, signed_manifest: bytes) -> None: ...
    def get_manifest(self, file_id: str) -> bytes: ...
```

- **Content addressing**: an object's name is the SHA-256 of the ciphertext, so the on-chain ctHash is also the download address. No URL or path is stored on-chain, and identical content is stored once.
- Storage holds only ciphertext objects and signed manifests: no keys, plaintext or file names.
- The services layer hashes everything it reads again (V1) and never trusts the store.
- Writes go to a temporary file followed by `os.replace`, so a crash never leaves half a file.
- ctHash (64 hex characters) and fileId (`0x` + 64 hex characters) are checked with a regex before any path is built, which blocks path traversal such as `../../keystore`.
- Size limit of 50 MB; larger files are refused with a message.
- The GUI's Security demo page (`SFS_DEMO=1`) edits files in this folder directly: flip one bit, change the manifest, delete, then restore with one click. Rollback to an older version (S9) is covered by pytest.

**For a demo on two computers (optional, not implemented)**, a local folder cannot be shared. Two options:

1. `scripts/storage_server.py`: an HTTP storage service on one computer (standard `http.server` or FastAPI, about 80 lines) offering only `PUT /objects`, `GET /objects/{ctHash}` and `PUT/GET /manifests/{fileId}`. The client switches to an `HttpObjectStore`; the services layer stays the same. The service is just as untrusted and stores only ciphertext.
2. Point `STORAGE_DIR` at a folder that both computers sync (OneDrive, Dropbox, Google Drive). No code needed, and it matches the brief's "public cloud services". The downside is a sync delay of seconds to tens of seconds, which is hard to control in a demo.

Recommendation: start with the local folder and demo on one computer with two windows. Add option 1 only if time allows after the normal flow works. Skip IPFS: it needs a node or an API key for a pinning service and adds little to the marks.

---

## 3. Threat model (outline for report section 3)

**Assets**: plaintext files; DEKs; each user's three private keys and keystore password; integrity of on-chain records (who owns what, who is approved); the audit log; metadata (who asked whom for what).

**Attackers**

| ID | Attacker | Can |
|---|---|---|
| A1 | Curious or compromised storage provider | Read, modify, delete or roll back ciphertexts and manifests |
| A2 | Unauthorized registered user | Make any contract call: approve someone else's file, approve their own request, request repeatedly; read all on-chain data |
| A3 | Network or chain observer | See all transactions, calldata and events; front-run transactions on a public chain |
| A4 | Public key substitution attacker | Swap in their own key on the path where the owner fetches the requester's key (W7) |
| A5 | Requester who was approved and later revoked | Keep the DEK and plaintext they already obtained |

**Trusted components**: the user's computer and this client; the cryptography/OpenSSL implementation; the operating system's CSPRNG; blockchain consensus and ordering; the tested contract code; the data returned by the local RPC node (on Sepolia we must trust the RPC provider, which is listed as a limitation).

**Assumptions**: ECDLP on secp256k1 is hard; AES-256 and GCM are secure; SHA-256 is collision-resistant; users keep their keystore passwords safe; owners are responsible for content. A signature proves who signed, not that the content is true (W3: a blockchain faithfully stores wrong input).

**Out of scope**: malware on, or theft of, the user's computer (W4: end-to-end encryption does not protect endpoints); authorized users leaking plaintext on purpose; storage deleting files (detected, not prevented).

**STRIDE → controls**

| Threat | Control |
|---|---|
| Spoofing (posing as the owner, swapping public keys) | Only the holder of an address can register its keys; verification keys are read from the chain; the contract checks `msg.sender == owner` for every decision |
| Tampering (ciphertext, manifest, rollback) | On-chain ctHash and manifestHash, ECDSA signature, GCM tag, salted plaintext digest |
| Repudiation | Every important action is a signed transaction that emits an event |
| Information disclosure | Client-side encryption; the DEK appears only as ECIES ciphertext; the file name is inside the ciphertext; no plaintext hash on-chain |
| Denial of service | No loops and no external calls in the contract; the fileId includes `msg.sender`, so front-running cannot take someone else's fileId |
| Elevation of privilege | `onlyFileOwner` modifier; the state machine rejects invalid transitions; no admin and no upgrade path |

---

## 4. Cryptographic design

### 4.1 User keys

| Key | Algorithm | Used only for | Public key goes to |
|---|---|---|---|
| `K_eth` | secp256k1 (Ethereum account) | Signing transactions and paying gas | The address |
| `K_sig` | ECDSA secp256k1 + SHA-256 | Signing file manifests | On-chain via `registerKeys` |
| `K_enc` | secp256k1 ECDH | Receiving ECIES-wrapped DEKs | On-chain via `registerKeys` |

**Why three keys**:
- Using `K_eth` to sign arbitrary 32-byte hashes is dangerous: the same operation could be tricked into signing a transaction, which is why Ethereum has the EIP-191 prefix. With separate keys, a leaked file signature affects neither funds nor on-chain rights.
- `K_enc` can be replaced on its own (call `registerKeys` again) without changing the account address (limitation 11 in section 11 says what this breaks).
- Each key is exposed differently, so separating them limits the damage of a single leak (W4 key hierarchy, blast radius).

**Keystore** (`keystore/<alias>.json`, git-ignored):

```json
{ "version": 1, "address": "0x…",
  "kdf": { "name": "scrypt", "n": 131072, "r": 8, "p": 1, "salt": "<16-byte hex>" },
  "cipher": { "name": "AES-256-GCM", "nonce": "<12-byte hex>" },
  "ciphertext": "<GCM(key from password, {eth_sk, sig_sk, enc_sk})>" }
```

- Password → scrypt → 32-byte key → AES-256-GCM. A wrong password fails the GCM check. The message is always "wrong password or corrupted keystore" and never says which.
- Private keys come from `secrets`/OpenSSL. **Never `random`**: the `random.randint` used in Labs 3 and 4 is a Mersenne Twister, whose output can be predicted.
- One keystore works on both chains. On the local chain, the GUI's "Add 100 test ETH" button (`anvil_setBalance`) funds the address; on Sepolia, use a faucet or transfer between accounts. Anvil's development keys are public fixed values, used only to deploy the contract and never stored in a user keystore.
- There is no script to import an existing private key (the planned `scripts/import_key.py`). A keystore created in the GUI comes with a new address; on Sepolia, send it test ETH from a Lab 1 or MetaMask account. No plaintext private key enters this project.

### 4.2 File encryption (AES-256-GCM)

```
DEK      = os.urandom(32)                                  # one per file
salt32   = os.urandom(32)                                  # used to derive the fileId
fileId   = keccak256(abi.encode(owner, salt32))            # same as the contract
header   = canonical_json({name, mime, size, salt: os.urandom(16)})
P        = len(header) (4 bytes, big-endian) ‖ header ‖ file_bytes
AAD      = "SFS-v1" ‖ chainId (32 bytes) ‖ contract (20) ‖ fileId (32) ‖ owner (20)
nonce    = os.urandom(12)
object   = "SFS1" ‖ nonce ‖ AESGCM(DEK).encrypt(nonce, P, AAD)   # ends with the 16-byte tag
ctHash   = SHA-256(object)        → stored as objects/<ctHash>.bin
```

- **Why GCM**: one operation gives both confidentiality and integrity; changing any byte makes decryption fail with `InvalidTag`. CTR only encrypts: an attacker who flips ciphertext bits flips the same plaintext bits.
- **Nonce**: each DEK encrypts exactly one object, so a random nonce cannot collide. A new version of a file would get a new DEK.
- **AAD**: binds the ciphertext to its chain, contract, file and owner. If storage swaps file A's ciphertext for file B's, decryption fails.
- **File name inside P**: neither storage nor chain observers see it. The random 16-byte salt in P stops anyone from confirming a guessed file against the plaintext digest (see 4.3).
- **Limit**: the whole file is read into memory, which is fine at demo sizes (the app accepts up to 50 MB). Streaming encryption is future work.

### 4.3 Digital signatures (ECDSA secp256k1)

The signed object is canonical JSON (sorted keys, no whitespace):

```json
{ "schema": "sfs-manifest/1", "chainId": 31337, "contract": "0x…",
  "fileId": "0x…", "owner": "0x…",
  "ctHash": "<SHA-256(object)>", "ctSize": 12345,
  "ptDigest": "<SHA-256(P)>", "enc": "AES-256-GCM", "createdAt": 1760000000 }
```

```
σ = ECDSA_Sign(K_sig, SHA-256(manifest_bytes))              # (r, s)
manifests/<fileId>.json = { manifest, signature: {r, s} }   # the signing public key is not stored
manifestHash = SHA-256(manifest_bytes)                      → on-chain
```

**What the requester checks, in order** (the GUI marks each one ✓ or ✗):

| Step | Check | Detects |
|---|---|---|
| V1 | SHA-256(downloaded object) == on-chain ctHash | Storage changed the ciphertext or rolled it back |
| V2 | SHA-256(manifest) == on-chain manifestHash | Changed manifest |
| V3 | fileId, owner, chainId, contract and ctHash in the manifest match the chain | Manifest moved from another file or chain |
| V4 | ECDSA_Verify(owner's `sigPubKey` **as registered on-chain**, manifest, σ) | Forged signature; an attacker re-signing with their own key |
| Key | Unwrap the DEK (section 6) | A wrapped key made for another file or person |
| V5 | AES-GCM decryption, tag valid | Damaged ciphertext, wrong AAD |
| V6 | SHA-256(P) == manifest.ptDigest | Confirms the content is what the owner signed, so an owner cannot give different requesters different content |

Saving is enabled only when every check passes.

**Rationale**:
- The signature covers both the ciphertext hash (checked before decryption) and the plaintext digest (confirms the content after decryption). This matches the brief's "retrieved file corresponds to the data originally signed".
- The verification key comes only from the chain, never from anything in storage. That is why V4 catches an attacker who re-signs.
- The nonce k is derived from the private key and the message as in RFC 6979 (`deterministic_signing=True` in cryptography), so it does not depend on runtime randomness (W3: a repeated or biased nonce leaks the private key).
- ECDSA signatures are malleable: (r, s) and (r, N−s) are both valid. We never use a signature as an identifier, so this does no harm. Still, signatures are normalized to low s, and verification accepts only low s.
- **Link to Lab 3**: a test verifies our signatures again with py_ecc using Lab 3's formula `X = u1·G + u2·Q, r ≡ X.x mod N`. Handy if the demo asks you to verify a signature by hand.

### 4.4 Improvements over the lab code (good material for the report)

| Lab practice | Problem | This project |
|---|---|---|
| `random.randint` for private keys and the ECDSA nonce (Labs 3/4) | Not a cryptographic RNG; predictable, so private keys can be recovered | Private keys from the OpenSSL CSPRNG; ECDSA nonce derived as in RFC 6979 |
| AES-CTR with `Counter.new(128)` starting from the same value every time (Lab 4) | Repeated keystream; no integrity | AES-256-GCM, random nonce, AAD |
| `SHA-256(str(k))` as the session key (Lab 4) | No KDF, no context binding | HKDF-SHA256 with info bound to fileId and requester |
| Public keys exchanged directly over TCP (Lab 4) | A man in the middle can swap keys (W6) | Keys registered on-chain by the address holder |
| `pickle.loads` on network data (Lab 4) | Arbitrary code execution | Only JSON and fixed binary formats |
| Private keys in plain JSON files (Labs 1/3/4) | A leaked file leaks the key | Keystore encrypted with scrypt + AES-GCM |
| Pure-Python point arithmetic in py_ecc | Not constant-time; side-channel risk | cryptography (OpenSSL); py_ecc only for cross-checks in tests |

---

## 5. Blockchain and smart contract

### 5.1 Networks (decided)

| Stage | Chain | Purpose |
|---|---|---|
| Development and automated tests | Anvil local chain (chainId 31337, `anvil --state .chain/state.json`) | forge test, pytest integration tests, debugging, live modification tasks |
| Final evidence | Sepolia (chainId 11155111) | Deploy the final version, run the normal flow and the unauthorized cases, take Etherscan screenshots (list in 10.4) |
| Demo | Sepolia first, local chain as backup | Switch to the local chain within a minute if the network or RPC fails |

**Switching networks**: two config files, `.env.local` and `.env.sepolia`, each with `RPC_URL`, `CHAIN_ID`, `CONTRACT_ADDRESS`, `DEPLOY_BLOCK` and `EXPLORER_URL`. The login page has a network drop-down. The code has no chain-specific constants.

**Sepolia notes**

- **Accounts and test ETH**: at least three accounts, Alice (owner), Bob (requester) and Mallory (unauthorized), each with Sepolia ETH for gas. Measure the gas of each function on the local chain with `forge test --gas-report`, then estimate the ETH needed from the current gas price. Faucets often have daily limits or require a mainnet balance, so **claim test ETH in the first week**. A Lab 1 account with a balance can send ETH to the others.
- **Deployment**: create an encrypted keystore with `cast wallet import` and deploy with `python scripts/deploy.py --network sepolia --keystore …` (see `contracts/README.md`), so no private key appears on the command line or in `.env`. Remix + MetaMask, as in Lab 2, also works. `deploy.py` writes the contract address and block number into `.env.sepolia`.
- **Source verification**: Verify & Publish the source on Etherscan. Etherscan then shows decoded function names (for example Approve Access), and the marker can read the contract there. The Etherscan API key is a secret: keep it in `.env`, never in git.
- **RPC**: the public node from Lab 1, `https://ethereum-sepolia-rpc.publicnode.com`, works but is rate-limited, and `eth_getLogs` limits the block range. Events are read from `DEPLOY_BLOCK` in chunks of 5000 blocks. Get a free Alchemy or Infura endpoint as a backup and keep its API key in `.env`.
- **Slow blocks**: about 12 seconds per block. After sending a transaction, the GUI shows the tx hash and an Etherscan link at once, then the block and gas once confirmed, and a warning after 120 seconds. Each account sends one transaction at a time, to avoid nonce clashes.
- **Deploy early**: Sepolia completed the Glamsterdam upgrade on 6 October. Deploy a test version on day 2 or 3 to confirm that the compiler, web3.py and the RPC all work.
- **Windows team members**: Foundry needs Git Bash or WSL. Otherwise use `npx hardhat node` instead of Anvil; the Python side only needs a different RPC URL.

### 5.2 Contract interface (`contracts/src/SecureFileShare.sol`)

The implemented contract adds a few input checks; see "Differences from DESIGN.md 5.2 / 5.3" in `contracts/README.md`.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract SecureFileShare {
    enum Status { None, Pending, Approved, Rejected, Revoked }

    struct UserKeys   { bytes sigPubKey; bytes encPubKey; }            // 33-byte compressed keys
    struct FileRecord { address owner; uint64 registeredAt; bool active;
                        bytes32 ctHash; bytes32 manifestHash; bytes ownerWrappedKey; }
    struct Request    { Status status; uint64 updatedAt; bytes wrappedKey; }

    uint256 public constant WRAPPED_KEY_LEN = 93;                      // 33 + 12 + 32 + 16

    mapping(address => UserKeys) private _keys;
    mapping(bytes32 => FileRecord) private _files;
    mapping(bytes32 => mapping(address => Request)) private _requests;

    error InvalidPublicKey();
    error KeysNotRegistered(address user);
    error FileAlreadyExists(bytes32 fileId);
    error FileNotFound(bytes32 fileId);
    error FileInactive(bytes32 fileId);
    error NotFileOwner(bytes32 fileId, address caller);
    error OwnerCannotRequest();
    error InvalidStatus(Status current);
    error InvalidWrappedKey();

    event KeysRegistered(address indexed user, bytes sigPubKey, bytes encPubKey);
    event FileRegistered(bytes32 indexed fileId, address indexed owner,
                         bytes32 ctHash, bytes32 manifestHash, string publicLabel);
    event AccessRequested(bytes32 indexed fileId, address indexed requester);
    event AccessApproved (bytes32 indexed fileId, address indexed requester);
    event AccessRejected (bytes32 indexed fileId, address indexed requester);
    event AccessRevoked  (bytes32 indexed fileId, address indexed requester);
    event FileDeactivated(bytes32 indexed fileId);

    modifier onlyFileOwner(bytes32 fileId) {
        address owner = _files[fileId].owner;
        if (owner == address(0)) revert FileNotFound(fileId);
        if (owner != msg.sender) revert NotFileOwner(fileId, msg.sender);
        _;
    }

    function registerKeys(bytes calldata sigPubKey, bytes calldata encPubKey) external;
    function registerFile(bytes32 salt, bytes32 ctHash, bytes32 manifestHash,
                          bytes calldata ownerWrappedKey, string calldata publicLabel)
        external returns (bytes32 fileId);        // fileId = keccak256(abi.encode(msg.sender, salt))
    function requestAccess(bytes32 fileId) external;
    function approveAccess(bytes32 fileId, address requester, bytes calldata wrappedKey)
        external onlyFileOwner(fileId);
    function rejectAccess(bytes32 fileId, address requester) external onlyFileOwner(fileId);
    function revokeAccess(bytes32 fileId, address requester) external onlyFileOwner(fileId);
    function deactivateFile(bytes32 fileId) external onlyFileOwner(fileId);

    // views: getUserKeys(addr) · getFile(fileId) · getRequest(fileId, requester)
}
```

A complete function:

```solidity
function approveAccess(bytes32 fileId, address requester, bytes calldata wrappedKey)
    external onlyFileOwner(fileId)
{
    Request storage req = _requests[fileId][requester];
    if (req.status != Status.Pending) revert InvalidStatus(req.status);
    if (wrappedKey.length != WRAPPED_KEY_LEN) revert InvalidWrappedKey();
    req.status = Status.Approved;
    req.updatedAt = uint64(block.timestamp);
    req.wrappedKey = wrappedKey;
    emit AccessApproved(fileId, requester);
}
```

### 5.3 Rules enforced by each function

| Function | Caller | Preconditions (otherwise it reverts) | Effect |
|---|---|---|---|
| `registerKeys` | Anyone | Both keys are 33 bytes and start with 0x02 or 0x03 | Sets or replaces the keys of `msg.sender` |
| `registerFile` | Anyone, who becomes the owner | Keys registered; ctHash and manifestHash non-zero; ownerWrappedKey is 93 bytes; fileId unused | New file record, `active = true` |
| `requestAccess` | Anyone except the owner | File exists and is active; caller has registered keys; status is None, Rejected or Revoked | → Pending |
| `approveAccess` | **Owner only** | Status is Pending; wrappedKey is 93 bytes | → Approved, wrappedKey stored |
| `rejectAccess` | **Owner only** | Status is Pending | → Rejected |
| `revokeAccess` | **Owner only** | Status is Approved | → Revoked, wrappedKey deleted |
| `deactivateFile` | **Owner only** | File is active | No new requests |

- **The fileId includes `msg.sender`**: on a public chain, someone who front-runs with the same salt gets a different fileId and cannot take the owner's.
- A requester who calls `approveAccess` on their own request reverts because they are not the owner. This is how the brief's "unauthorized users cannot approve" is guaranteed.

### 5.4 Request state machine

```
            requestAccess              approveAccess (owner)
   None ───────────────► Pending ───────────────────────► Approved
     ▲                     │                                 │
     │                     │ rejectAccess (owner)            │ revokeAccess (owner)
     │                     ▼                                 ▼
     │                 Rejected ──┐                       Revoked ──┐
     │                            │ requestAccess                    │ requestAccess
     └────────────────────────────┴──────────► Pending ◄─────────────┘
```

**Invariants** (checked by forge invariant and fuzz tests): `wrappedKey` is non-empty ⇔ `status == Approved`; no address other than the owner can move a request out of Pending.

### 5.5 Audit trail

- Events record what the brief requires (file registration, access requests, approval and rejection), plus revocation, deactivation and key registration.
- The GUI's Activity page reads the logs with `get_logs` from the deploy block to the latest block. It shows block number, transaction hash, event, file and account, and exports CSV as evidence for the report.
- After every transaction, the GUI shows its receipt (tx hash, block, gasUsed).

### 5.6 Contract security

- No ETH comes in or goes out and no other contract is called, so there is no reentrancy surface. (The reentrancy and unchecked-call issues from W2 do not apply; explain why in the report.)
- **No admin, no upgrade, no pause**: no privileged key can change other people's data. (The bridge thefts in W2 came from lost admin keys.)
- Solidity 0.8 checks overflow; every input is checked for length and non-zero values; state-changing functions have no loops, so gas is bounded.
- Custom errors let the GUI turn reverts into plain messages (for example "Only the owner of file … can do this").
- `forge test` covers every revert branch; `slither .` runs static analysis, with the results in the report appendix.

---

## 6. Secure key sharing (ECIES)

### 6.1 Protocol

When the owner approves Bob's request:

```
1. encPub_B   ← contract.getUserKeys(Bob).encPubKey
               (from_encoded_point rejects points that are not on the curve: no invalid-curve attack)
2. e          ← random scalar; E = e·G (33-byte compressed)
3. Z          = ECDH(e, encPub_B)                    # x-coordinate of the shared point, 32 bytes
4. KEK        = HKDF-SHA256(IKM = Z,
                            salt = E ‖ encPub_B,
                            info = "SFS-keywrap-v1" ‖ chainId ‖ contract ‖ fileId ‖ Bob,
                            L = 32)
5. n          ← os.urandom(12)
6. C          = AES-256-GCM(KEK, n, DEK, AAD = fileId ‖ Bob)     # 32 bytes + 16-byte tag
7. wrappedKey = E ‖ n ‖ C                              # 33 + 12 + 48 = 93 bytes
8. approveAccess(fileId, Bob, wrappedKey)              # transaction signed by the owner's account
```

Bob computes `Z = ECDH(k_B, E)` with `K_enc`, derives the same KEK, and decrypts the DEK with GCM.

**The owner's own copy**: when registering a file, the owner also wraps the DEK for themselves (`ownerWrappedKey`). With just the keystore, the owner can recover every DEK on a new computer, and no DEK is stored locally. Every authorized party uses the same model of one wrapped key per person (W4 per-recipient wrapping).

### 6.2 Why this design

| Question | Answer |
|---|---|
| Why not Lab 4's interactive DH? | Lab 4 needs both sides online over TCP, but a requester may be offline. ECIES needs only the recipient's public key: it is non-interactive |
| How is man-in-the-middle prevented? | Receiving side: Bob's key is registered by a transaction from Bob's address, so no one else can change it. Sending side: a wrapped key can only be written by `approveAccess`, and the contract checks that the caller is the owner. Both ends are authenticated, which answers W6's "How to solve the problem? (hint: authentication)" |
| Why a new ephemeral key e every time? | The KEKs of two wraps are unrelated, and the owner's long-term key is not involved, so a leak of it does not expose wrapped keys already sent |
| Why put fileId and Bob in the HKDF info? | A wrapped key moved from file A to file B, or handed to Carol, derives a different KEK and fails the AAD, so unwrapping fails |
| Why can the wrapped key be public on-chain? | Without `k_B` no one can compute Z (ECDLP/CDH assumption), and GCM detects tampering. The brief allows this: "encrypted key material may be stored on the blockchain" |
| Alternatives | RSA-OAEP: one more key type to manage, and 256-byte ciphertexts cost more gas. X25519: equally good; we chose secp256k1 to match the course. DEK in a `private` contract variable: **insecure**, anyone can read storage slots. ABE or proxy re-encryption (W4): suited to large groups, future work |

### 6.3 Revocation and long-term security

- `revokeAccess` sets the status to Revoked and deletes the stored wrapped key; the GUI no longer offers the download.
- **History cannot be erased**: the calldata of the approve transaction stays on-chain forever, and a DEK Bob already obtained still works (W4: "Revocation cannot erase plaintext already obtained").
- The real way to cut off future access: the owner encrypts again with a new DEK, registers a new version, and wraps it only for people who are still authorized. This was planned as an optional "Rotate file key" feature. It is not implemented (limitation 2 in section 11).
- No forward secrecy: if Bob's `K_enc` leaks later, every wrapped key ever sent to Bob can be opened. Mitigation: replace `K_enc` from time to time (`registerKeys`), and keep the old keystore to open earlier wrapped keys.

---

## 7. End-to-end flow

```mermaid
sequenceDiagram
    autonumber
    participant O as Owner (Alice) GUI
    participant S as Off-chain Storage
    participant C as SecureFileShare
    participant R as Requester (Bob) GUI

    Note over O,R: 0. First use: each registers keys with registerKeys(sigPub, encPub)
    O->>O: Create DEK and fileId; encrypt with AES-256-GCM; sign the manifest
    O->>S: put(object) → ctHash; put(manifest + σ)
    O->>C: registerFile(salt, ctHash, manifestHash, ownerWrappedKey, label)
    C-->>R: event FileRegistered
    R->>C: requestAccess(fileId)
    C-->>O: event AccessRequested
    O->>C: getUserKeys(Bob) → encPub_B (the GUI shows its fingerprint to confirm)
    O->>O: Unwrap own DEK → wrap it for Bob with ECIES
    O->>C: approveAccess(fileId, Bob, wrappedKey)
    C-->>R: event AccessApproved
    R->>C: getFile / getRequest / getUserKeys(Alice)
    R->>S: get(object), get(manifest + σ)
    R->>R: V1–V4 → unwrap DEK → decrypt → V5–V6 → save plaintext
```

Rejection: the owner calls `rejectAccess`; Bob's GUI shows Rejected and offers no key.

---

## 8. GUI design (Tkinter)

The app starts on a login page, then shows a sidebar with one page per task (`app/gui/app.py`).

- **Login**: choose or create a keystore, enter the password and pick the network. The sidebar then shows the address, network and balance; a banner asks for "Register keys" when the keys are not on-chain yet.
- **Owner pages**
  - *Protect a file*: a list of steps that fills in as each one finishes: ① encrypted (algorithm, ciphertext size) ② signed (manifest hash) ③ uploaded (ctHash) ④ registered on-chain (tx hash, block, gas).
  - *My files*: my files and, for the selected file, its requests with requester address, encryption-key fingerprint, time and status. Approve, Reject and Revoke appear according to the status. Approve first opens a confirmation dialog with the file, the requester's address and the key fingerprint (W3: the signing screen is part of the security boundary, so users must see what they approve).
- **Requester pages**
  - *Browse files*: every registered file (short fileId, owner, public label, time, my status), searchable by name, file ID or owner. "Request access"; the status updates by itself, because the app polls for new events every 3 seconds on the local chain and once a block on Sepolia.
  - *Retrieve and verify*: after approval, reads the approved request and its 93-byte wrapped key, runs V1–V4, unwraps the file key, then runs V5–V6. Each check shows ✓ or ✗ and the reason for any failure. "Save decrypted file" is enabled only when every check passes.
- **Activity**: the contract's events as a timeline, exportable as CSV.
- **Account**: key fingerprints, network and balance.
- **Security demo** (only with `SFS_DEMO=1` or `--demo`): tamper with stored objects, and try to approve another owner's file with the current account, to show failure handling live.

**Interaction rules**
- Transactions, encryption and decryption run on worker threads; results return to the Tk thread through `after()`. Buttons that would send another transaction are disabled while one is pending, so nothing is submitted twice.
- Contract custom errors become readable messages. Users never see a stack trace; details go to the log, which never contains key material.
- The GUI never shows a private key or a DEK, only fingerprints (the first 8 bytes of SHA-256).
- Every tx hash opens its page on `EXPLORER_URL` with `webbrowser.open`; without an explorer (local chain) the hash is copied instead.
- The sidebar always shows the network (Local or Sepolia), the address and the balance, and a banner warns when the balance is low.

### 8.1 Tkinter compatibility

Tkinter is part of the Python standard library and runs on Windows, macOS and Linux; quiz2 and quiz3 already run on your Mac. The real issues are Tk versions, appearance and threading:

| Problem | Platform | Fix |
|---|---|---|
| Old Tk on recent macOS ignores clicks or draws incorrectly | macOS (common with the system Python) | Use the conda-forge environment: `python=3.11`, `tk>=8.6.13`. The app checks `info patchlevel` at start and warns |
| Homebrew Python has no tkinter | macOS | Use the conda environment, or `brew install python-tk` |
| The distribution's Python has no tkinter | Linux | `sudo apt install python3-tk`, or use conda |
| Blurry text on high-DPI screens | Windows | Call `ctypes.windll.shcore.SetProcessDpiAwareness(1)` at start |
| The default aqua theme ignores button colours | macOS | The app draws its own controls on canvases (`app/gui/widgets.py`), so no ttk theme is involved |
| Fonts differ per platform | All | Use the platform's default UI font and the first available monospace font from a list (`app/gui/theme.py`) |
| The window freezes while waiting for a transaction | All | Tk is not thread-safe. Chain calls and crypto run on worker threads; results go into a `queue.Queue` that the Tk thread drains with `after()` (the quiz3 pattern). A Sepolia confirmation takes 10–30 seconds, so this has to work |
| ✓ and ✗ symbols | Windows | Icons are drawn on canvases (`app/gui/icons.py`), so no symbol font or emoji is needed |
| Non-ASCII paths and file names | Windows | Always use `pathlib`, and read and write files as bytes |

**Requirement**: by 19 Oct, every team member runs "an empty window + read the block number from the local chain" in the conda environment on their own system. Windows users should test early.

---

## 9. Project structure

```
assignment/
├── README.md                      # setup, running, two-user demo, tests and the S1–S16 test table
├── DESIGN.md                      # this document (Chinese version: DESIGN.zh.md)
├── contracts/                     # Foundry project
│   ├── src/SecureFileShare.sol
│   ├── test/                      # Registration · AccessControl · Fuzz · invariant/
│   ├── lib/forge-std              # committed, so no install is needed after cloning
│   └── foundry.toml
├── app/
│   ├── config.py                  # reads .env.local or .env.sepolia for the chosen network, plus STORAGE_DIR
│   ├── crypto/   aead.py · signing.py · ecies.py · keystore.py · encoding.py
│   ├── storage/  object_store.py (local folder)
│   ├── chain/    client.py · errors.py · events.py · abi/SecureFileShare.json
│   ├── services/ models.py · account.py · owner.py · requester.py · verification.py
│   └── gui/      app.py · login_view.py · owner_view.py · protect_view.py · requester_view.py
│                 verify_view.py · audit_view.py · account_view.py · demo_view.py · widgets.py · theme.py …
├── tests/        unit/ · integration/
├── scripts/      start_chain.sh · deploy.py
├── evidence/     EVIDENCE.md (test and scan results), logs/, collect.sh
├── .env.local / .env.sepolia      # network settings, not in git (an RPC URL may contain an API key)
├── .env.example                   # template in git, placeholders only
├── .gitignore                     # keystore/ .env* storage/ .chain/ (except .env.example)
└── environment.yml                # conda environment secure-file-share
```

**Changes from the original plan**: the GUI replaces `create_users.py` (create a keystore on the login page; on the local chain, click "Add 100 test ETH"). The Security demo page and the S1–S16 tests in forge and pytest replace `attack_*.py` and `tests/security/`; README.md maps each scenario to its tests. `import_key.py`, `http_store.py`, `storage_server.py` and `start_local_demo.sh` were not built.

**Dependencies**: `cryptography`, `web3`, `eth-account`, `python-dotenv`, `pytest`; for tests also `py_ecc` (Lab 3 cross-check) and `bandit`. Tools: Foundry, Slither, Gitleaks.

**Coding conventions** (same as quiz2/quiz3): records are `@dataclass(frozen=True)`; files of about 200–400 lines; `services` return structured results (one result object per verification step), and the GUI only renders them.

**Secrets** (W9): keystores and `.env` files stay out of git; `.env.example` holds only non-sensitive values such as RPC URLs; run Gitleaks before committing; deployment keys come only from a keystore or an environment variable, never from code.

---

## 10. Test plan

### 10.1 Normal workflow

| Level | Tool | What |
|---|---|---|
| Unit | pytest | AEAD round trip; ECDSA sign and verify; ECIES wrap and unwrap; keystore create and unlock; stable canonical manifests |
| Cross-check | pytest + py_ecc | Verify our signatures independently with Lab 3's formula |
| Contract | forge test | The normal path and every revert branch of each function; fuzzing: no random address can approve, reject or revoke someone else's file |
| Integration | pytest + Anvil | Alice registers → Bob requests → Alice approves → Bob verifies and decrypts, byte-identical plaintext; the reject branch; the revoke branch |
| Manual | GUI | The whole flow in two windows, with screenshots |

### 10.2 Security and failure test matrix (the key table of the report)

| ID | Scenario | Expected result | Detected by |
|---|---|---|---|
| S1 | Mallory calls `approveAccess` on Alice's file | revert `NotFileOwner` | Contract |
| S2 | Bob approves his own request | revert `NotFileOwner` | Contract |
| S3 | Approve twice, or approve a rejected request | revert `InvalidStatus` | Contract |
| S4 | Owner requests own file; request for a missing file; request without registered keys | Matching revert | Contract |
| S5 | Register the same salt twice | revert `FileAlreadyExists` | Contract |
| S6 | Flip one byte of the stored ciphertext | V1 fails; forced decryption fails with GCM `InvalidTag` | Client |
| S7 | Change ptDigest in the manifest | V2 fails, V4 fails | Client |
| S8 | Attacker re-signs a forged manifest with their own `K_sig` | V4 fails (the verification key comes from the chain) | Client |
| S9 | Roll the object back to an older version of the same file | V1 fails | Client |
| S10 | Mallory reads Bob's wrapped key from the chain and tries her own `K_enc` | GCM `InvalidTag` | Client |
| S11 | Use file A's wrapped key for file B | HKDF info and AAD differ, unwrapping fails | Client |
| S12 | A rejected or revoked user asks for the key | No wrapped key on-chain; the GUI refuses | Contract + GUI |
| S13 | Wrong keystore password | Not unlocked; the message does not say why | Client |
| S14 | Register an invalid public key (wrong length or prefix, or not on the curve) | Contract reverts / client refuses | Contract + client |
| S15 | Replay an approve transaction that was already mined | The node rejects the used nonce (W3) | Blockchain |
| S16 | Front-running: someone else registers with the same salt | Different fileId; the owner is unaffected | Contract |

All of S1–S16 have automated tests: contract-side in forge, client-side in pytest. README.md's "Security test matrix" maps each scenario to its tests, and `evidence/EVIDENCE.md` records the results. For the live demo, use the GUI's Security demo page (`SFS_DEMO=1`): tamper with storage (S6, S7, a deleted object) and call approveAccess without permission (S1, S2; optionally broadcast it, so the failed transaction is mined).

### 10.3 Static analysis and scanning

- Slither: the contract (W10 static analysis).
- Bandit: the Python code.
- Gitleaks: the whole repository and its git history (W9 hard-coded secrets).

### 10.4 Sepolia evidence checklist

The contract freezes on 24 Oct. After deploying it to Sepolia, run these steps and take screenshots:

| # | Action | Screenshot |
|---|---|---|
| E1 | Deploy the contract, Verify & Publish the source | Contract page (green tick) and deployment transaction |
| E2 | Alice and Bob each call `registerKeys` once | Transaction list with decoded function names |
| E3 | Alice `registerFile` → Bob `requestAccess` → Alice `approveAccess` | The three transactions and their events in the Logs tab |
| E4 | Another file: Bob requests → Alice `rejectAccess`; then `revokeAccess` on an earlier approval | Transactions and events |
| E5 | Input Data of the `approveAccess` transaction | Only the 93-byte wrapped key ciphertext is on-chain, no plaintext DEK: the most direct evidence of on-chain privacy |
| E6 | Unauthorized cases: S1 (Mallory approves), S2 (Bob approves himself), S3 (approve twice) | Transactions with status Fail, plus the revert reason shown on the Security demo page |

**How E6 puts failed transactions on-chain**: web3.py estimates gas before sending, so a call that would revert is stopped locally and never reaches the chain. The Security demo page's "Broadcast anyway" option sends it with a fixed gas limit instead, so the transaction is mined and shows Fail (test: `test_broadcast_failing_transaction_for_evidence`). Failed transactions still cost gas.

The page covers S1 and S2. The GUI never offers a second approval, so S3 needs a few lines of Python that call `ChainClient.transact(..., gas_limit=...)` with the owner's account; no script for this is included.

Summarize them in the report as a table: action, tx hash, block, gasUsed, result.

---

## 11. Limitations (material for report section 10)

1. The endpoint is trusted: malware can read plaintext after decryption, which end-to-end encryption cannot prevent (W4).
2. Authorized users can leak plaintext. Revocation cannot recall a DEK already sent; only a new DEK protects later versions, and the client has no "Rotate file key" feature for that.
3. On-chain metadata: who owns which file, who asked whom and when form a public social graph. Addresses are pseudonymous but can be linked.
4. Wrapped keys stay on-chain forever, so their security depends on the recipient's `K_enc` never leaking. There is no forward secrecy.
5. The client trusts the data its RPC node returns: a single node on the local chain, a public RPC provider on Sepolia.
6. An address is only a hash of a public key, not a real-world identity. Fingerprints must be checked out of band, or a PKI added (W7).
7. Python cannot reliably wipe keys from memory.
8. Storage can delete files: this is detected, not prevented; preventing it would need replicas (W4 resilience).
9. Whole files are read into memory, so very large files are not supported.
10. Storage is a local folder that simulates cloud storage, with no replication, access control or access log.
11. Replacing on-chain keys breaks older files: V4 checks against the owner's current signing key, and keys wrapped for an old encryption key open only with the old keystore.
12. Registering a public key does not require proof that the caller holds the private key. Someone can register another person's public key as their own, but gains nothing: they still cannot sign or decrypt with it.

---

## 12. Roles and timeline (planned on Fri 16 Oct; due Wed 28 Oct, 11:30 pm)

| Role | Responsible for | Main output |
|---|---|---|
| A Contract | Contract, forge tests (including fuzz and invariant), deploy script, Slither | `contracts/`, `scripts/deploy.py` |
| B Cryptography | All `crypto/` modules, unit tests, Lab 3 cross-check | `app/crypto/`, `tests/unit/` |
| C Integration | Chain client, storage, owner and requester workflows, integration tests | `app/chain/`, `app/storage/`, `app/services/` |
| D GUI | Pages, threading, error messages, screenshots | `app/gui/` |
| E Security and report | Threat model, security test matrix, Security demo page, report editing, evidence | README's S1–S16 table, `app/gui/demo_view.py`, `evidence/`, the report |

With fewer than five people, merge C+E or D+E. Each person is assessed individually in the demo, so **everyone must be able to explain the whole design**. At the daily stand-up, take turns explaining someone else's module.

| Dates | Milestone |
|---|---|
| Fri 16 – Sat 17 Oct | Finalize the design; agree on the interfaces (ABI, wrappedKey format, manifest schema, AAD format); set up the conda environment and Foundry; **get Sepolia test ETH for 3 or more accounts** |
| Sun 18 – Tue 20 Oct | Parallel work: contract + forge tests / crypto + unit tests / storage + chain client / GUI skeleton. By 19 Oct everyone runs Tkinter + the local chain; **deploy to Sepolia once as a trial** |
| Wed 21 – Fri 23 Oct | Integration: the full flow from the command line, then in the GUI. **The normal flow must work on the local chain by 23 Oct** |
| Sat 24 – Sun 25 Oct | Contract freeze; security test matrix and static analysis; deploy to Sepolia, verify the source, collect evidence as in 10.4 |
| Mon 26 – Tue 27 Oct | Finish the report (at most 20 pages); rehearse the demo on Sepolia, practise switching to the local chain, quiz each other |
| Wed 28 Oct | Buffer; submit before 11:30 pm |

---

## 13. Report outline (at most 20 pages, references excluded)

| Section | Content | Pages |
|---|---|---|
| 1 | Introduction & scope | 0.5 |
| 2 | System architecture (architecture diagram, on-chain vs off-chain table) | 2 |
| 3 | Threat model (assets, attackers, trusted components, assumptions, STRIDE table) | 2 |
| 4 | Cryptographic design (keys, AES-GCM, signatures, improvements over the labs) | 3 |
| 5 | Blockchain & smart contract (interface, rules table, state machine, events, on-chain privacy) | 3 |
| 6 | Secure key sharing (ECIES protocol diagram, rationale, revocation) | 2 |
| 7 | GUI (4–6 screenshots, each with its feedback points marked) | 2 |
| 8 | Implementation (modules, dependencies, secret management; no long code listings) | 1 |
| 9 | Testing & evaluation (normal flow, S1–S16 table, transaction records, Slither) | 2.5 |
| 10 | Security analysis & limitations | 1.5 |
| 11 | Conclusion | 0.5 |

Choose the screenshots that show the most, one per kind. Show only key code fragments (for example `approveAccess` and the ECIES wrap).

---

## 14. Demo preparation

**Likely questions**
- Why GCM instead of Lab 4's CTR?
- The wrapped key is public on-chain. Why is that safe?
- How does the owner know they have Bob's real public key?
- What happens when a non-owner calls `approveAccess`? (Show the revert live.)
- Can Bob still decrypt after revocation?
- Why separate the signing key from the transaction key?
- What exactly is signed? What does each of V1–V6 protect against?
- Which data is on-chain, and why is the file name not?

**Sepolia demo checklist**
- The day before, check every account's balance and that both the main and the backup RPC respond.
- Prepare a registered file and a pending request on Sepolia in advance, so the demo only waits for a few key transactions.
- Use the 10–20 seconds of each confirmation to explain the current step.
- Backup: prepare data on the local chain in advance with `scripts/start_chain.sh` (the state is saved to `.chain/state.json` every 5 seconds and on exit), then switch to Local on the login page and resume within a minute.

**Possible live modification tasks** (do them on the local chain; never deploy to Sepolia during the demo. The code is modular, and `scripts/start_chain.sh` + `deploy.py` redeploy in seconds)
- Add an expiry time to approvals (an `expiresAt` field and a `hasAccess` view).
- Add an event, or a cooldown for `requestAccess`.
- Change the HKDF info and explain why old wrapped keys no longer open.
- Verify a signature by hand with Lab 3's formula.
- Change one byte and say which step fails.
- Remove `onlyFileOwner` and run forge test to see which tests fail.

---

## 15. Decisions and open questions

**Decided (16 Oct)**
- Network: local chain for development and automated tests; the final version on Sepolia for evidence; the demo on Sepolia with the local chain as backup (5.1).
- UI: Tkinter desktop app (8, 8.1).
- Storage: a local folder that simulates cloud object storage (2.2).

**Open**
1. Anvil or Hardhat node for the local chain: depends on whether Windows members can install Foundry; the Python side only needs another RPC URL. (The scripts and tests currently use Anvil.)
2. Demo on two computers? That needs the HTTP storage service or a synced cloud folder (2.2).
3. Optional extras, only after the normal flow works (none implemented yet):
   - Storage checks authorization: before a download, the client signs a random challenge with `K_eth`, and the service returns data only if the chain says Approved (W6 challenge-response, W9 passkey idea), as defence in depth;
   - Approval expiry;
   - File key rotation (a new DEK after a revocation).
