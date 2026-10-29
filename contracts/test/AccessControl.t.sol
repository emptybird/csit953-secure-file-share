// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseTest} from "./utils/BaseTest.sol";
import {SecureFileShare} from "../src/SecureFileShare.sol";

/// @notice Request state machine, owner-only checks and deactivation.
contract AccessControlTest is BaseTest {
    bytes32 internal fileId;

    function setUp() public override {
        super.setUp();
        fileId = _registerFile(alice, SALT);
    }

    // -------------------------------------------------------- requestAccess

    function test_requestAccess_setsPendingAndEmits() public {
        vm.warp(1_760_000_100);
        vm.expectEmit(true, true, false, false, address(share));
        emit SecureFileShare.AccessRequested(fileId, bob);
        _request(fileId, bob);

        SecureFileShare.Request memory req = share.getRequest(fileId, bob);
        assertEq(uint8(req.status), uint8(SecureFileShare.Status.Pending));
        assertEq(req.updatedAt, 1_760_000_100);
        assertEq(req.wrappedKey.length, 0);
    }

    function test_requestAccess_unknownFileReverts() public {
        bytes32 unknown = keccak256("unknown");
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(SecureFileShare.FileNotFound.selector, unknown));
        share.requestAccess(unknown);
    }

    function test_requestAccess_ownerCannotRequestOwnFile() public {
        vm.prank(alice);
        vm.expectRevert(SecureFileShare.OwnerCannotRequest.selector);
        share.requestAccess(fileId);
    }

    function test_requestAccess_requiresRegisteredKeys() public {
        vm.prank(nobody);
        vm.expectRevert(abi.encodeWithSelector(SecureFileShare.KeysNotRegistered.selector, nobody));
        share.requestAccess(fileId);
    }

    function test_requestAccess_rejectsDuplicatePending() public {
        _request(fileId, bob);
        vm.prank(bob);
        vm.expectRevert(_invalidStatus(SecureFileShare.Status.Pending));
        share.requestAccess(fileId);
    }

    function test_requestAccess_rejectsWhenAlreadyApproved() public {
        _request(fileId, bob);
        _approve(fileId, alice, bob);
        vm.prank(bob);
        vm.expectRevert(_invalidStatus(SecureFileShare.Status.Approved));
        share.requestAccess(fileId);
    }

    function test_requestAccess_allowedAgainAfterReject() public {
        _request(fileId, bob);
        _reject(fileId, alice, bob);
        _request(fileId, bob);
        _assertStatus(fileId, bob, SecureFileShare.Status.Pending);
    }

    function test_requestAccess_allowedAgainAfterRevoke() public {
        _request(fileId, bob);
        _approve(fileId, alice, bob);
        _revoke(fileId, alice, bob);
        _request(fileId, bob);
        _assertStatus(fileId, bob, SecureFileShare.Status.Pending);
        assertEq(share.getRequest(fileId, bob).wrappedKey.length, 0);
    }

    // -------------------------------------------------------- approveAccess

    function test_approveAccess_storesWrappedKeyAndEmits() public {
        _request(fileId, bob);
        bytes memory wrapped = _wrappedKey(keccak256("bob-dek"));

        vm.expectEmit(true, true, false, false, address(share));
        emit SecureFileShare.AccessApproved(fileId, bob);
        vm.prank(alice);
        share.approveAccess(fileId, bob, wrapped);

        SecureFileShare.Request memory req = share.getRequest(fileId, bob);
        assertEq(uint8(req.status), uint8(SecureFileShare.Status.Approved));
        assertEq(req.wrappedKey, wrapped);
    }

    function test_strangerCannotApprove() public {
        _request(fileId, bob);
        vm.prank(mallory);
        vm.expectRevert(_notOwner(fileId, mallory));
        share.approveAccess(fileId, bob, _wrappedKey(SALT));
        _assertStatus(fileId, bob, SecureFileShare.Status.Pending);
    }

    function test_requesterCannotApproveOwnRequest() public {
        _request(fileId, bob);
        vm.prank(bob);
        vm.expectRevert(_notOwner(fileId, bob));
        share.approveAccess(fileId, bob, _wrappedKey(SALT));
        _assertStatus(fileId, bob, SecureFileShare.Status.Pending);
    }

    function test_cannotApproveTwice() public {
        _request(fileId, bob);
        _approve(fileId, alice, bob);
        vm.prank(alice);
        vm.expectRevert(_invalidStatus(SecureFileShare.Status.Approved));
        share.approveAccess(fileId, bob, _wrappedKey(SALT));
    }

    function test_cannotApproveRejectedRequest() public {
        _request(fileId, bob);
        _reject(fileId, alice, bob);
        vm.prank(alice);
        vm.expectRevert(_invalidStatus(SecureFileShare.Status.Rejected));
        share.approveAccess(fileId, bob, _wrappedKey(SALT));
    }

    function test_approveAccess_requiresPendingRequest() public {
        vm.prank(alice);
        vm.expectRevert(_invalidStatus(SecureFileShare.Status.None));
        share.approveAccess(fileId, carol, _wrappedKey(SALT));
    }

    function test_approveAccess_rejectsBadWrappedKeyLength() public {
        _request(fileId, bob);
        bytes memory tooShort = new bytes(92);
        vm.prank(alice);
        vm.expectRevert(SecureFileShare.InvalidWrappedKey.selector);
        share.approveAccess(fileId, bob, tooShort);
    }

    function test_approveAccess_unknownFileReverts() public {
        bytes32 unknown = keccak256("unknown");
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(SecureFileShare.FileNotFound.selector, unknown));
        share.approveAccess(unknown, bob, _wrappedKey(SALT));
    }

    function test_approveAccess_inactiveFileReverts() public {
        _request(fileId, bob);
        vm.prank(alice);
        share.deactivateFile(fileId);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(SecureFileShare.FileInactive.selector, fileId));
        share.approveAccess(fileId, bob, _wrappedKey(SALT));
    }

    function test_approvalIsPerRequester() public {
        _request(fileId, bob);
        _request(fileId, carol);
        _approve(fileId, alice, bob);

        _assertStatus(fileId, bob, SecureFileShare.Status.Approved);
        _assertStatus(fileId, carol, SecureFileShare.Status.Pending);
        assertEq(share.getRequest(fileId, carol).wrappedKey.length, 0);
    }

    // --------------------------------------------------------- rejectAccess

    function test_rejectAccess_setsRejectedAndEmits() public {
        _request(fileId, bob);
        vm.expectEmit(true, true, false, false, address(share));
        emit SecureFileShare.AccessRejected(fileId, bob);
        _reject(fileId, alice, bob);
        _assertStatus(fileId, bob, SecureFileShare.Status.Rejected);
    }

    function test_rejectAccess_onlyOwner() public {
        _request(fileId, bob);
        vm.prank(mallory);
        vm.expectRevert(_notOwner(fileId, mallory));
        share.rejectAccess(fileId, bob);
    }

    function test_rejectAccess_requiresPending() public {
        _request(fileId, bob);
        _approve(fileId, alice, bob);
        vm.prank(alice);
        vm.expectRevert(_invalidStatus(SecureFileShare.Status.Approved));
        share.rejectAccess(fileId, bob);
    }

    // --------------------------------------------------------- revokeAccess

    function test_revokeAccess_deletesWrappedKeyAndEmits() public {
        _request(fileId, bob);
        _approve(fileId, alice, bob);

        vm.expectEmit(true, true, false, false, address(share));
        emit SecureFileShare.AccessRevoked(fileId, bob);
        _revoke(fileId, alice, bob);

        _assertStatus(fileId, bob, SecureFileShare.Status.Revoked);
        assertEq(share.getRequest(fileId, bob).wrappedKey.length, 0);
    }

    function test_revokeAccess_onlyOwner() public {
        _request(fileId, bob);
        _approve(fileId, alice, bob);
        vm.prank(bob);
        vm.expectRevert(_notOwner(fileId, bob));
        share.revokeAccess(fileId, bob);
        _assertStatus(fileId, bob, SecureFileShare.Status.Approved);
    }

    function test_revokeAccess_requiresApproved() public {
        _request(fileId, bob);
        vm.prank(alice);
        vm.expectRevert(_invalidStatus(SecureFileShare.Status.Pending));
        share.revokeAccess(fileId, bob);
    }

    function test_rejectedAndRevokedRequestersHoldNoWrappedKey() public {
        _request(fileId, bob);
        _reject(fileId, alice, bob);
        _request(fileId, carol);
        _approve(fileId, alice, carol);
        _revoke(fileId, alice, carol);

        assertEq(share.getRequest(fileId, bob).wrappedKey.length, 0);
        assertEq(share.getRequest(fileId, carol).wrappedKey.length, 0);
    }

    // ------------------------------------------------------- deactivateFile

    function test_deactivateFile_blocksNewRequestsAndEmits() public {
        vm.expectEmit(true, false, false, false, address(share));
        emit SecureFileShare.FileDeactivated(fileId);
        vm.prank(alice);
        share.deactivateFile(fileId);

        assertFalse(share.getFile(fileId).active);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(SecureFileShare.FileInactive.selector, fileId));
        share.requestAccess(fileId);
    }

    function test_deactivateFile_onlyOwner() public {
        vm.prank(mallory);
        vm.expectRevert(_notOwner(fileId, mallory));
        share.deactivateFile(fileId);
        assertTrue(share.getFile(fileId).active);
    }

    function test_deactivateFile_revertsWhenAlreadyInactive() public {
        vm.startPrank(alice);
        share.deactivateFile(fileId);
        vm.expectRevert(abi.encodeWithSelector(SecureFileShare.FileInactive.selector, fileId));
        share.deactivateFile(fileId);
        vm.stopPrank();
    }

    function test_deactivateFile_ownerCanStillRejectAndRevoke() public {
        _request(fileId, bob);
        _request(fileId, carol);
        _approve(fileId, alice, carol);
        vm.prank(alice);
        share.deactivateFile(fileId);

        _reject(fileId, alice, bob);
        _revoke(fileId, alice, carol);
        _assertStatus(fileId, bob, SecureFileShare.Status.Rejected);
        _assertStatus(fileId, carol, SecureFileShare.Status.Revoked);
    }

    // ------------------------------------------------------------ lifecycle

    function test_fullLifecycleUpdatesTimestamps() public {
        vm.warp(1000);
        _request(fileId, bob);
        vm.warp(2000);
        _reject(fileId, alice, bob);
        assertEq(share.getRequest(fileId, bob).updatedAt, 2000);

        vm.warp(3000);
        _request(fileId, bob);
        vm.warp(4000);
        _approve(fileId, alice, bob);
        assertEq(share.getRequest(fileId, bob).updatedAt, 4000);

        vm.warp(5000);
        _revoke(fileId, alice, bob);
        SecureFileShare.Request memory req = share.getRequest(fileId, bob);
        assertEq(uint8(req.status), uint8(SecureFileShare.Status.Revoked));
        assertEq(req.updatedAt, 5000);
    }
}
