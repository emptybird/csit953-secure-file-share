// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CommonBase} from "forge-std/Base.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {StdUtils} from "forge-std/StdUtils.sol";
import {SecureFileShare} from "../../src/SecureFileShare.sol";

/// @dev Drives random sequences of calls from a fixed set of actors and keeps a
///      reference model of what each call should do. Calls go through try/catch,
///      so a disagreement with the model is counted instead of reverting the run.
contract SecureFileShareHandler is CommonBase, StdCheats, StdUtils {
    /// Few salts per owner, so duplicate registrations happen regularly.
    uint256 internal constant SALT_SPACE = 3;
    bytes32 internal constant CT_HASH = keccak256("ciphertext-object");
    bytes32 internal constant MANIFEST_HASH = keccak256("signed-manifest");

    SecureFileShare public immutable share;
    bytes internal _wrappedKey;
    address[] internal _actors;
    bytes32[] internal _fileIds;

    mapping(address => bool) public hasKeys;
    mapping(bytes32 => address) public ownerOf;
    mapping(bytes32 => bool) public isActive;
    mapping(bytes32 => mapping(address => SecureFileShare.Status)) public expectedStatus;

    /// Calls whose success or failure disagreed with the reference model.
    uint256 public modelMismatches;
    /// Owner-only calls that succeeded although the caller was not the owner.
    uint256 public unauthorizedSuccesses;

    constructor(SecureFileShare share_) {
        share = share_;
        _wrappedKey = abi.encodePacked(bytes1(0x02), keccak256("e"), bytes12(0), keccak256("c"), bytes16(0));

        address[4] memory registered = [makeAddr("alice"), makeAddr("bob"), makeAddr("carol"), makeAddr("mallory")];
        for (uint256 i = 0; i < registered.length; i++) {
            address user = registered[i];
            vm.prank(user);
            share.registerKeys(
                abi.encodePacked(bytes1(0x02), keccak256(abi.encode("sig", user))),
                abi.encodePacked(bytes1(0x03), keccak256(abi.encode("enc", user)))
            );
            hasKeys[user] = true;
            _actors.push(user);
        }
        _actors.push(makeAddr("nobody")); // never registers keys
    }

    // -------------------------------------------------------------- actions

    function registerFile(uint256 ownerSeed, uint256 saltSeed) external {
        address owner = _actor(ownerSeed);
        bytes32 salt = bytes32(saltSeed % SALT_SPACE);
        bytes32 fileId = share.computeFileId(owner, salt);
        bool expected = hasKeys[owner] && ownerOf[fileId] == address(0);

        vm.prank(owner);
        try share.registerFile(salt, CT_HASH, MANIFEST_HASH, _wrappedKey, "") returns (bytes32 id) {
            _check(expected && id == fileId);
            ownerOf[id] = owner;
            isActive[id] = true;
            _fileIds.push(id);
        } catch {
            _check(!expected);
        }
    }

    function requestAccess(uint256 requesterSeed, uint256 fileSeed) external {
        if (_fileIds.length == 0) return;
        bytes32 fileId = _file(fileSeed);
        address requester = _actor(requesterSeed);
        SecureFileShare.Status current = expectedStatus[fileId][requester];
        bool expected = isActive[fileId] && requester != ownerOf[fileId] && hasKeys[requester]
            && (current == SecureFileShare.Status.None
                || current == SecureFileShare.Status.Rejected
                || current == SecureFileShare.Status.Revoked);

        vm.prank(requester);
        try share.requestAccess(fileId) {
            _check(expected);
            expectedStatus[fileId][requester] = SecureFileShare.Status.Pending;
        } catch {
            _check(!expected);
        }
    }

    function approveAccess(uint256 callerSeed, uint256 fileSeed, uint256 requesterSeed) external {
        if (_fileIds.length == 0) return;
        bytes32 fileId = _file(fileSeed);
        address caller = _callerFor(fileId, callerSeed);
        address requester = _actor(requesterSeed);
        bool isOwner = caller == ownerOf[fileId];
        bool expected =
            isOwner && isActive[fileId] && expectedStatus[fileId][requester] == SecureFileShare.Status.Pending;

        vm.prank(caller);
        try share.approveAccess(fileId, requester, _wrappedKey) {
            _recordOwnerOnlySuccess(isOwner, expected);
            expectedStatus[fileId][requester] = SecureFileShare.Status.Approved;
        } catch {
            _check(!expected);
        }
    }

    function rejectAccess(uint256 callerSeed, uint256 fileSeed, uint256 requesterSeed) external {
        if (_fileIds.length == 0) return;
        bytes32 fileId = _file(fileSeed);
        address caller = _callerFor(fileId, callerSeed);
        address requester = _actor(requesterSeed);
        bool isOwner = caller == ownerOf[fileId];
        bool expected = isOwner && expectedStatus[fileId][requester] == SecureFileShare.Status.Pending;

        vm.prank(caller);
        try share.rejectAccess(fileId, requester) {
            _recordOwnerOnlySuccess(isOwner, expected);
            expectedStatus[fileId][requester] = SecureFileShare.Status.Rejected;
        } catch {
            _check(!expected);
        }
    }

    function revokeAccess(uint256 callerSeed, uint256 fileSeed, uint256 requesterSeed) external {
        if (_fileIds.length == 0) return;
        bytes32 fileId = _file(fileSeed);
        address caller = _callerFor(fileId, callerSeed);
        address requester = _actor(requesterSeed);
        bool isOwner = caller == ownerOf[fileId];
        bool expected = isOwner && expectedStatus[fileId][requester] == SecureFileShare.Status.Approved;

        vm.prank(caller);
        try share.revokeAccess(fileId, requester) {
            _recordOwnerOnlySuccess(isOwner, expected);
            expectedStatus[fileId][requester] = SecureFileShare.Status.Revoked;
        } catch {
            _check(!expected);
        }
    }

    function deactivateFile(uint256 callerSeed, uint256 fileSeed) external {
        if (_fileIds.length == 0) return;
        bytes32 fileId = _file(fileSeed);
        address caller = _callerFor(fileId, callerSeed);
        bool isOwner = caller == ownerOf[fileId];
        bool expected = isOwner && isActive[fileId];

        vm.prank(caller);
        try share.deactivateFile(fileId) {
            _recordOwnerOnlySuccess(isOwner, expected);
            isActive[fileId] = false;
        } catch {
            _check(!expected);
        }
    }

    // ---------------------------------------------------------- inspection

    function fileCount() external view returns (uint256) {
        return _fileIds.length;
    }

    function fileIdAt(uint256 index) external view returns (bytes32) {
        return _fileIds[index];
    }

    function actorCount() external view returns (uint256) {
        return _actors.length;
    }

    function actorAt(uint256 index) external view returns (address) {
        return _actors[index];
    }

    // ------------------------------------------------------------- helpers

    function _actor(uint256 seed) internal view returns (address) {
        return _actors[seed % _actors.length];
    }

    function _file(uint256 seed) internal view returns (bytes32) {
        return _fileIds[seed % _fileIds.length];
    }

    /// Half the time the real owner, otherwise any actor, so that both the
    /// authorized path and the unauthorized path are exercised.
    function _callerFor(bytes32 fileId, uint256 seed) internal view returns (address) {
        return seed % 2 == 0 ? ownerOf[fileId] : _actor(seed / 2);
    }

    function _check(bool ok) internal {
        if (!ok) modelMismatches++;
    }

    function _recordOwnerOnlySuccess(bool isOwner, bool expected) internal {
        if (!isOwner) unauthorizedSuccesses++;
        _check(expected);
    }
}
