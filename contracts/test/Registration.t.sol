// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseTest} from "./utils/BaseTest.sol";
import {SecureFileShare} from "../src/SecureFileShare.sol";

/// @notice registerKeys, registerFile and the read-only views.
contract RegistrationTest is BaseTest {
    // --------------------------------------------------------- registerKeys

    function test_registerKeys_storesKeysAndEmits() public {
        address dave = makeAddr("dave");
        vm.expectEmit(true, false, false, true, address(share));
        emit SecureFileShare.KeysRegistered(dave, _sigKey(dave), _encKey(dave));
        _registerKeys(dave);

        SecureFileShare.UserKeys memory keys = share.getUserKeys(dave);
        assertEq(keys.sigPubKey, _sigKey(dave));
        assertEq(keys.encPubKey, _encKey(dave));
    }

    function test_registerKeys_rotationReplacesKeys() public {
        bytes memory newEnc = abi.encodePacked(bytes1(0x02), keccak256("bob-enc-v2"));
        vm.prank(bob);
        share.registerKeys(_sigKey(bob), newEnc);

        assertEq(share.getUserKeys(bob).encPubKey, newEnc);
    }

    function test_S14_registerKeys_rejectsWrongLength() public {
        bytes memory short = abi.encodePacked(bytes1(0x02), bytes31(keccak256("x")));
        bytes memory uncompressed = abi.encodePacked(bytes1(0x04), keccak256("x"), keccak256("y"));

        vm.startPrank(nobody);
        vm.expectRevert(SecureFileShare.InvalidPublicKey.selector);
        share.registerKeys(short, _encKey(nobody));
        vm.expectRevert(SecureFileShare.InvalidPublicKey.selector);
        share.registerKeys(_sigKey(nobody), uncompressed);
        vm.expectRevert(SecureFileShare.InvalidPublicKey.selector);
        share.registerKeys("", "");
        vm.stopPrank();
    }

    function test_S14_registerKeys_rejectsBadPrefix() public {
        bytes memory prefix04 = abi.encodePacked(bytes1(0x04), keccak256("x"));
        bytes memory prefix00 = abi.encodePacked(bytes1(0x00), keccak256("x"));

        vm.startPrank(nobody);
        vm.expectRevert(SecureFileShare.InvalidPublicKey.selector);
        share.registerKeys(prefix04, _encKey(nobody));
        vm.expectRevert(SecureFileShare.InvalidPublicKey.selector);
        share.registerKeys(_sigKey(nobody), prefix00);
        vm.stopPrank();
    }

    function test_registerKeys_rejectsSameKeyForBothPurposes() public {
        vm.prank(nobody);
        vm.expectRevert(SecureFileShare.InvalidPublicKey.selector);
        share.registerKeys(_sigKey(nobody), _sigKey(nobody));
    }

    function test_getUserKeys_emptyForUnregisteredUser() public view {
        SecureFileShare.UserKeys memory keys = share.getUserKeys(nobody);
        assertEq(keys.sigPubKey.length, 0);
        assertEq(keys.encPubKey.length, 0);
    }

    // --------------------------------------------------------- registerFile

    function test_registerFile_storesRecordAndEmits() public {
        bytes32 expectedId = keccak256(abi.encode(alice, SALT));
        vm.warp(1_760_000_000);

        vm.expectEmit(true, true, false, true, address(share));
        emit SecureFileShare.FileRegistered(expectedId, alice, CT_HASH, MANIFEST_HASH, LABEL);
        bytes32 fileId = _registerFile(alice, SALT);

        assertEq(fileId, expectedId);
        assertEq(fileId, share.computeFileId(alice, SALT));
        SecureFileShare.FileRecord memory file = share.getFile(fileId);
        assertEq(file.owner, alice);
        assertEq(file.registeredAt, 1_760_000_000);
        assertTrue(file.active);
        assertEq(file.ctHash, CT_HASH);
        assertEq(file.manifestHash, MANIFEST_HASH);
        assertEq(file.ownerWrappedKey, _wrappedKey(SALT));
    }

    function test_registerFile_emptyLabelAllowed() public {
        vm.prank(alice);
        share.registerFile(SALT, CT_HASH, MANIFEST_HASH, _wrappedKey(SALT), "");
    }

    function test_registerFile_maxLabelAllowed() public {
        string memory label = string(new bytes(share.MAX_LABEL_LEN()));
        vm.prank(alice);
        share.registerFile(SALT, CT_HASH, MANIFEST_HASH, _wrappedKey(SALT), label);
    }

    function test_registerFile_rejectsLongLabel() public {
        string memory label = string(new bytes(share.MAX_LABEL_LEN() + 1));
        vm.prank(alice);
        vm.expectRevert(SecureFileShare.LabelTooLong.selector);
        share.registerFile(SALT, CT_HASH, MANIFEST_HASH, _wrappedKey(SALT), label);
    }

    function test_registerFile_requiresRegisteredKeys() public {
        vm.prank(nobody);
        vm.expectRevert(abi.encodeWithSelector(SecureFileShare.KeysNotRegistered.selector, nobody));
        share.registerFile(SALT, CT_HASH, MANIFEST_HASH, _wrappedKey(SALT), LABEL);
    }

    function test_registerFile_rejectsZeroHashes() public {
        vm.startPrank(alice);
        vm.expectRevert(SecureFileShare.InvalidHash.selector);
        share.registerFile(SALT, bytes32(0), MANIFEST_HASH, _wrappedKey(SALT), LABEL);
        vm.expectRevert(SecureFileShare.InvalidHash.selector);
        share.registerFile(SALT, CT_HASH, bytes32(0), _wrappedKey(SALT), LABEL);
        vm.stopPrank();
    }

    function test_registerFile_rejectsBadOwnerWrappedKeyLength() public {
        bytes memory tooShort = new bytes(92);
        bytes memory tooLong = new bytes(94);

        vm.startPrank(alice);
        vm.expectRevert(SecureFileShare.InvalidWrappedKey.selector);
        share.registerFile(SALT, CT_HASH, MANIFEST_HASH, tooShort, LABEL);
        vm.expectRevert(SecureFileShare.InvalidWrappedKey.selector);
        share.registerFile(SALT, CT_HASH, MANIFEST_HASH, tooLong, LABEL);
        vm.expectRevert(SecureFileShare.InvalidWrappedKey.selector);
        share.registerFile(SALT, CT_HASH, MANIFEST_HASH, "", LABEL);
        vm.stopPrank();
    }

    function test_S5_registerFile_rejectsDuplicateSalt() public {
        bytes32 fileId = _registerFile(alice, SALT);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(SecureFileShare.FileAlreadyExists.selector, fileId));
        share.registerFile(SALT, keccak256("other-ct"), MANIFEST_HASH, _wrappedKey(SALT), LABEL);
    }

    function test_S16_frontRunWithSameSaltGetsDifferentFileId() public {
        bytes32 malloryId = _registerFile(mallory, SALT);
        bytes32 aliceId = _registerFile(alice, SALT);

        assertTrue(malloryId != aliceId);
        assertEq(share.getFile(aliceId).owner, alice);
        assertEq(share.getFile(malloryId).owner, mallory);
    }

    // ---------------------------------------------------------------- views

    function test_getFile_revertsForUnknownFile() public {
        bytes32 unknown = keccak256("unknown");
        vm.expectRevert(abi.encodeWithSelector(SecureFileShare.FileNotFound.selector, unknown));
        share.getFile(unknown);
    }

    function test_getRequest_noneForUnknownPair() public view {
        SecureFileShare.Request memory req = share.getRequest(keccak256("unknown"), bob);
        assertEq(uint8(req.status), uint8(SecureFileShare.Status.None));
        assertEq(req.updatedAt, 0);
        assertEq(req.wrappedKey.length, 0);
    }

    function test_constants() public view {
        assertEq(share.PUBKEY_LEN(), 33);
        assertEq(share.WRAPPED_KEY_LEN(), 33 + 12 + 32 + 16);
    }
}
