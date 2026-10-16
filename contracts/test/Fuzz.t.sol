// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseTest} from "./utils/BaseTest.sol";
import {SecureFileShare} from "../src/SecureFileShare.sol";

/// @notice Property tests over random callers, keys and byte strings.
contract FuzzTest is BaseTest {
    /// Any address other than the owner is refused by every owner-only function.
    function testFuzz_S1_nonOwnerCannotManageFile(address caller) public {
        vm.assume(caller != alice);
        bytes32 fileId = _registerFile(alice, SALT);
        _request(fileId, bob);
        bytes memory err = _notOwner(fileId, caller);

        vm.startPrank(caller);
        vm.expectRevert(err);
        share.approveAccess(fileId, bob, _wrappedKey(SALT));
        vm.expectRevert(err);
        share.rejectAccess(fileId, bob);
        vm.expectRevert(err);
        share.deactivateFile(fileId);
        vm.stopPrank();
        _assertStatus(fileId, bob, SecureFileShare.Status.Pending);

        _approve(fileId, alice, bob);
        vm.prank(caller);
        vm.expectRevert(err);
        share.revokeAccess(fileId, bob);
        _assertStatus(fileId, bob, SecureFileShare.Status.Approved);
    }

    function testFuzz_registerKeys_rejectsMalformedKey(bytes calldata key) public {
        vm.assume(!(key.length == 33 && (key[0] == 0x02 || key[0] == 0x03)));

        vm.startPrank(nobody);
        vm.expectRevert(SecureFileShare.InvalidPublicKey.selector);
        share.registerKeys(key, _encKey(nobody));
        vm.expectRevert(SecureFileShare.InvalidPublicKey.selector);
        share.registerKeys(_sigKey(nobody), key);
        vm.stopPrank();
    }

    function testFuzz_registerKeys_acceptsCompressedKeys(bytes32 sigX, bytes32 encX, bool sigOdd, bool encOdd) public {
        vm.assume(sigX != encX || sigOdd != encOdd);
        bytes memory sig = abi.encodePacked(sigOdd ? bytes1(0x03) : bytes1(0x02), sigX);
        bytes memory enc = abi.encodePacked(encOdd ? bytes1(0x03) : bytes1(0x02), encX);

        vm.prank(nobody);
        share.registerKeys(sig, enc);
        assertEq(share.getUserKeys(nobody).sigPubKey, sig);
        assertEq(share.getUserKeys(nobody).encPubKey, enc);
    }

    function testFuzz_approveAccess_rejectsWrongWrappedKeyLength(bytes calldata wrappedKey) public {
        vm.assume(wrappedKey.length != 93);
        bytes32 fileId = _registerFile(alice, SALT);
        _request(fileId, bob);

        vm.prank(alice);
        vm.expectRevert(SecureFileShare.InvalidWrappedKey.selector);
        share.approveAccess(fileId, bob, wrappedKey);
    }

    function testFuzz_registerFile_rejectsWrongWrappedKeyLength(bytes calldata wrappedKey) public {
        vm.assume(wrappedKey.length != 93);
        vm.prank(alice);
        vm.expectRevert(SecureFileShare.InvalidWrappedKey.selector);
        share.registerFile(SALT, CT_HASH, MANIFEST_HASH, wrappedKey, LABEL);
    }

    /// Front-running the owner's salt yields another fileId and cannot block the owner.
    function testFuzz_S16_fileIdIsBoundToSender(address attacker, bytes32 salt) public {
        vm.assume(attacker != alice);
        _registerKeys(attacker);
        bytes32 attackerId = _registerFile(attacker, salt);
        bytes32 aliceId = _registerFile(alice, salt);

        assertTrue(attackerId != aliceId);
        assertEq(share.getFile(aliceId).owner, alice);
    }

    /// Clients compute the same id off-chain before encrypting (it goes into the AAD).
    function testFuzz_computeFileId_matchesAbiEncode(address owner, bytes32 salt) public view {
        assertEq(share.computeFileId(owner, salt), keccak256(abi.encode(owner, salt)));
    }
}
