// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SecureFileShare} from "../../src/SecureFileShare.sol";

/// @dev Shared fixture: Alice owns files, Bob and Carol request access, Mallory is a
///      registered but unauthorized user, and Nobody has never registered keys.
abstract contract BaseTest is Test {
    bytes32 internal constant SALT = keccak256("salt-1");
    bytes32 internal constant CT_HASH = keccak256("ciphertext-object");
    bytes32 internal constant MANIFEST_HASH = keccak256("signed-manifest");
    string internal constant LABEL = "week-5-notes";

    SecureFileShare internal share;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    address internal carol = makeAddr("carol");
    address internal mallory = makeAddr("mallory");
    address internal nobody = makeAddr("nobody");

    function setUp() public virtual {
        share = new SecureFileShare();
        _registerKeys(alice);
        _registerKeys(bob);
        _registerKeys(carol);
        _registerKeys(mallory);
    }

    // ------------------------------------------------------------- fixtures

    // Deterministic per-user keys: valid encoding, not real curve points. The
    // contract checks only the encoding.
    function _sigKey(address user) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes1(0x02), keccak256(abi.encode("sig", user)));
    }

    function _encKey(address user) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes1(0x03), keccak256(abi.encode("enc", user)));
    }

    /// @dev Same layout as a real ECIES wrap: E (33) | nonce (12) | ciphertext (32) | tag (16).
    function _wrappedKey(bytes32 seed) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes1(0x02), seed, bytes12(seed), keccak256(abi.encode(seed)), bytes16(seed));
    }

    // -------------------------------------------------------------- actions

    function _registerKeys(address user) internal {
        vm.prank(user);
        share.registerKeys(_sigKey(user), _encKey(user));
    }

    function _registerFile(address owner, bytes32 salt) internal returns (bytes32 fileId) {
        vm.prank(owner);
        fileId = share.registerFile(salt, CT_HASH, MANIFEST_HASH, _wrappedKey(salt), LABEL);
    }

    function _request(bytes32 fileId, address requester) internal {
        vm.prank(requester);
        share.requestAccess(fileId);
    }

    function _approve(bytes32 fileId, address owner, address requester) internal {
        vm.prank(owner);
        share.approveAccess(fileId, requester, _wrappedKey(keccak256(abi.encode(fileId, requester))));
    }

    function _reject(bytes32 fileId, address owner, address requester) internal {
        vm.prank(owner);
        share.rejectAccess(fileId, requester);
    }

    function _revoke(bytes32 fileId, address owner, address requester) internal {
        vm.prank(owner);
        share.revokeAccess(fileId, requester);
    }

    // ----------------------------------------------------------- assertions

    function _assertStatus(bytes32 fileId, address requester, SecureFileShare.Status expected) internal view {
        assertEq(uint8(share.getRequest(fileId, requester).status), uint8(expected), "request status");
    }

    // Expected revert payloads.
    function _notOwner(bytes32 fileId, address caller) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(SecureFileShare.NotFileOwner.selector, fileId, caller);
    }

    function _invalidStatus(SecureFileShare.Status current) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(SecureFileShare.InvalidStatus.selector, current);
    }
}
