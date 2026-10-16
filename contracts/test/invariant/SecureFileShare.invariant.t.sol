// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SecureFileShare} from "../../src/SecureFileShare.sol";
import {SecureFileShareHandler} from "./SecureFileShareHandler.sol";

/// @notice Stateful fuzzing of the request state machine (DESIGN.md 5.4).
contract SecureFileShareInvariantTest is Test {
    SecureFileShare internal share;
    SecureFileShareHandler internal handler;

    function setUp() public {
        share = new SecureFileShare();
        handler = new SecureFileShareHandler(share);

        bytes4[] memory selectors = new bytes4[](6);
        selectors[0] = SecureFileShareHandler.registerFile.selector;
        selectors[1] = SecureFileShareHandler.requestAccess.selector;
        selectors[2] = SecureFileShareHandler.approveAccess.selector;
        selectors[3] = SecureFileShareHandler.rejectAccess.selector;
        selectors[4] = SecureFileShareHandler.revokeAccess.selector;
        selectors[5] = SecureFileShareHandler.deactivateFile.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    /// No owner-only function ever succeeds for a caller other than the owner.
    function invariant_onlyOwnerChangesRequests() public view {
        assertEq(handler.unauthorizedSuccesses(), 0, "non-owner call succeeded");
    }

    /// Every call succeeded or reverted exactly as the reference model predicted.
    function invariant_callsFollowStateMachine() public view {
        assertEq(handler.modelMismatches(), 0, "call outcome differs from model");
    }

    /// Stored file records and request states equal the model.
    function invariant_stateMatchesModel() public view {
        for (uint256 i = 0; i < handler.fileCount(); i++) {
            bytes32 fileId = handler.fileIdAt(i);
            SecureFileShare.FileRecord memory file = share.getFile(fileId);
            assertEq(file.owner, handler.ownerOf(fileId), "owner");
            assertEq(file.active, handler.isActive(fileId), "active");

            for (uint256 j = 0; j < handler.actorCount(); j++) {
                address actor = handler.actorAt(j);
                assertEq(
                    uint8(share.getRequest(fileId, actor).status),
                    uint8(handler.expectedStatus(fileId, actor)),
                    "request status"
                );
            }
        }
    }

    /// wrappedKey is non-empty exactly when the request is Approved, and then 93 bytes.
    function invariant_wrappedKeyOnlyWhileApproved() public view {
        for (uint256 i = 0; i < handler.fileCount(); i++) {
            bytes32 fileId = handler.fileIdAt(i);
            for (uint256 j = 0; j < handler.actorCount(); j++) {
                SecureFileShare.Request memory req = share.getRequest(fileId, handler.actorAt(j));
                uint256 expectedLen = req.status == SecureFileShare.Status.Approved ? share.WRAPPED_KEY_LEN() : 0;
                assertEq(req.wrappedKey.length, expectedLen, "wrappedKey length");
            }
        }
    }
}
