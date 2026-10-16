// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SecureFileShare
/// @notice Registry and access-control state machine for the CSIT953 secure file
///         sharing system. Files are encrypted and signed off-chain; this contract
///         keeps the public keys, integrity hashes, request states and ECIES-wrapped
///         file keys, and only lets a file's owner approve, reject or revoke access.
/// @dev Everything stored or emitted here is public, `private` state included.
///      Wrapped keys stay confidential because of ECIES, not because of this
///      contract. There is no admin, no upgrade path, no ETH flow and no external call.
contract SecureFileShare {
    enum Status {
        None,
        Pending,
        Approved,
        Rejected,
        Revoked
    }

    struct UserKeys {
        bytes sigPubKey; // compressed secp256k1 key for ECDSA manifest signatures
        bytes encPubKey; // compressed secp256k1 key for receiving ECIES-wrapped DEKs
    }

    struct FileRecord {
        address owner;
        uint64 registeredAt;
        bool active;
        bytes32 ctHash; // SHA-256 of the stored ciphertext object
        bytes32 manifestHash; // SHA-256 of the canonical signed manifest
        bytes ownerWrappedKey; // the owner's own ECIES-wrapped copy of the DEK
    }

    struct Request {
        Status status;
        uint64 updatedAt;
        bytes wrappedKey; // non-empty only while status == Approved
    }

    uint256 public constant PUBKEY_LEN = 33;
    /// @dev ephemeral key (33) | GCM nonce (12) | encrypted DEK (32) | GCM tag (16)
    uint256 public constant WRAPPED_KEY_LEN = 93;
    uint256 public constant MAX_LABEL_LEN = 128;

    mapping(address => UserKeys) private _keys;
    mapping(bytes32 => FileRecord) private _files;
    mapping(bytes32 => mapping(address => Request)) private _requests;

    error InvalidPublicKey();
    error KeysNotRegistered(address user);
    error InvalidHash();
    error InvalidWrappedKey();
    error LabelTooLong();
    error FileAlreadyExists(bytes32 fileId);
    error FileNotFound(bytes32 fileId);
    error FileInactive(bytes32 fileId);
    error NotFileOwner(bytes32 fileId, address caller);
    error OwnerCannotRequest();
    error InvalidStatus(Status current);

    event KeysRegistered(address indexed user, bytes sigPubKey, bytes encPubKey);
    event FileRegistered(
        bytes32 indexed fileId, address indexed owner, bytes32 ctHash, bytes32 manifestHash, string publicLabel
    );
    event AccessRequested(bytes32 indexed fileId, address indexed requester);
    event AccessApproved(bytes32 indexed fileId, address indexed requester);
    event AccessRejected(bytes32 indexed fileId, address indexed requester);
    event AccessRevoked(bytes32 indexed fileId, address indexed requester);
    event FileDeactivated(bytes32 indexed fileId);

    modifier onlyFileOwner(bytes32 fileId) {
        _requireFileOwner(fileId);
        _;
    }

    // ---------------------------------------------------------------- users

    /// @notice Register or rotate the caller's signing and encryption public keys.
    /// @dev Binding keys to `msg.sender` stops anyone else from substituting them.
    ///      Only the encoding is checked here; clients must still reject points
    ///      that are not on the curve before using a key.
    function registerKeys(bytes calldata sigPubKey, bytes calldata encPubKey) external {
        if (!_isCompressedKey(sigPubKey) || !_isCompressedKey(encPubKey)) revert InvalidPublicKey();
        if (keccak256(sigPubKey) == keccak256(encPubKey)) revert InvalidPublicKey();

        _keys[msg.sender] = UserKeys({sigPubKey: sigPubKey, encPubKey: encPubKey});
        emit KeysRegistered(msg.sender, sigPubKey, encPubKey);
    }

    // ---------------------------------------------------------------- files

    /// @notice Register an encrypted file; the caller becomes its owner.
    /// @param salt Random value chosen by the owner; fileId = keccak256(abi.encode(owner, salt)).
    /// @param publicLabel Optional label that is only emitted, never stored. It is public.
    /// @return fileId Identifier of the new file record.
    function registerFile(
        bytes32 salt,
        bytes32 ctHash,
        bytes32 manifestHash,
        bytes calldata ownerWrappedKey,
        string calldata publicLabel
    ) external returns (bytes32 fileId) {
        if (!_hasKeys(msg.sender)) revert KeysNotRegistered(msg.sender);
        if (ctHash == bytes32(0) || manifestHash == bytes32(0)) revert InvalidHash();
        if (ownerWrappedKey.length != WRAPPED_KEY_LEN) revert InvalidWrappedKey();
        if (bytes(publicLabel).length > MAX_LABEL_LEN) revert LabelTooLong();

        // msg.sender is part of the id, so front-running the same salt cannot
        // claim the owner's fileId.
        fileId = computeFileId(msg.sender, salt);
        if (_files[fileId].owner != address(0)) revert FileAlreadyExists(fileId);

        _files[fileId] = FileRecord({
            owner: msg.sender,
            registeredAt: _now(),
            active: true,
            ctHash: ctHash,
            manifestHash: manifestHash,
            ownerWrappedKey: ownerWrappedKey
        });
        emit FileRegistered(fileId, msg.sender, ctHash, manifestHash, publicLabel);
    }

    /// @notice Stop accepting new requests or approvals for a file.
    /// @dev Existing requests can still be rejected or revoked.
    function deactivateFile(bytes32 fileId) external onlyFileOwner(fileId) {
        FileRecord storage file = _files[fileId];
        if (!file.active) revert FileInactive(fileId);

        file.active = false;
        emit FileDeactivated(fileId);
    }

    // ------------------------------------------------------------- requests

    /// @notice Ask the owner for access. Allowed from None, Rejected or Revoked.
    function requestAccess(bytes32 fileId) external {
        FileRecord storage file = _files[fileId];
        if (file.owner == address(0)) revert FileNotFound(fileId);
        if (!file.active) revert FileInactive(fileId);
        if (file.owner == msg.sender) revert OwnerCannotRequest();
        if (!_hasKeys(msg.sender)) revert KeysNotRegistered(msg.sender);

        Request storage req = _requests[fileId][msg.sender];
        Status current = req.status;
        if (current != Status.None && current != Status.Rejected && current != Status.Revoked) {
            revert InvalidStatus(current);
        }

        req.status = Status.Pending;
        req.updatedAt = _now();
        emit AccessRequested(fileId, msg.sender);
    }

    /// @notice Approve a pending request and publish the DEK wrapped for the requester.
    /// @param wrappedKey ECIES ciphertext of the DEK under the requester's encPubKey.
    function approveAccess(bytes32 fileId, address requester, bytes calldata wrappedKey)
        external
        onlyFileOwner(fileId)
    {
        if (!_files[fileId].active) revert FileInactive(fileId);
        Request storage req = _requests[fileId][requester];
        if (req.status != Status.Pending) revert InvalidStatus(req.status);
        if (wrappedKey.length != WRAPPED_KEY_LEN) revert InvalidWrappedKey();

        req.status = Status.Approved;
        req.updatedAt = _now();
        req.wrappedKey = wrappedKey;
        emit AccessApproved(fileId, requester);
    }

    /// @notice Reject a pending request. The requester may ask again later.
    function rejectAccess(bytes32 fileId, address requester) external onlyFileOwner(fileId) {
        Request storage req = _requests[fileId][requester];
        if (req.status != Status.Pending) revert InvalidStatus(req.status);

        req.status = Status.Rejected;
        req.updatedAt = _now();
        emit AccessRejected(fileId, requester);
    }

    /// @notice Revoke an approval and delete the stored wrapped key.
    /// @dev The approve transaction's calldata stays on-chain, and a DEK the
    ///      requester already recovered remains valid. Only re-encrypting the
    ///      file under a new DEK cuts off future access.
    function revokeAccess(bytes32 fileId, address requester) external onlyFileOwner(fileId) {
        Request storage req = _requests[fileId][requester];
        if (req.status != Status.Approved) revert InvalidStatus(req.status);

        req.status = Status.Revoked;
        req.updatedAt = _now();
        delete req.wrappedKey;
        emit AccessRevoked(fileId, requester);
    }

    // ---------------------------------------------------------------- views

    /// @notice Public keys of `user`; both are empty if the user never registered.
    function getUserKeys(address user) external view returns (UserKeys memory) {
        return _keys[user];
    }

    function getFile(bytes32 fileId) external view returns (FileRecord memory) {
        FileRecord memory file = _files[fileId];
        if (file.owner == address(0)) revert FileNotFound(fileId);
        return file;
    }

    /// @notice Request state of `requester` for `fileId`; Status.None if never requested.
    function getRequest(bytes32 fileId, address requester) external view returns (Request memory) {
        return _requests[fileId][requester];
    }

    /// @notice The fileId that `registerFile` derives; clients use it to build the AAD.
    function computeFileId(address owner, bytes32 salt) public pure returns (bytes32) {
        return keccak256(abi.encode(owner, salt));
    }

    // ------------------------------------------------------------- internal

    function _requireFileOwner(bytes32 fileId) private view {
        address owner = _files[fileId].owner;
        if (owner == address(0)) revert FileNotFound(fileId);
        if (owner != msg.sender) revert NotFileOwner(fileId, msg.sender);
    }

    function _hasKeys(address user) private view returns (bool) {
        return _keys[user].sigPubKey.length != 0;
    }

    function _isCompressedKey(bytes calldata key) private pure returns (bool) {
        return key.length == PUBKEY_LEN && (key[0] == 0x02 || key[0] == 0x03);
    }

    function _now() private view returns (uint64) {
        // casting to 'uint64' is safe because block timestamps stay below 2**64 for ~5e11 years
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(block.timestamp);
    }
}
