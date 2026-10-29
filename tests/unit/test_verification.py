"""V1-V6 pipeline without a chain: the anchor stands in for what the contract returns."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from pathlib import Path

import pytest

from app.crypto import aead, ecies, signing
from app.crypto.encoding import FileContext, canonical_json, compute_file_id, sha256
from app.crypto.keystore import UserKeys
from app.services import ServiceError
from app.services.models import Check, CheckResult, Outcome, RetrievedFile, VerificationReport
from app.services.requester import save_plaintext
from app.services.verification import Anchor, Fetched, verify_and_decrypt

CONTENT = b"quarterly numbers\n" * 50
NAME = "report.txt"
ALL_PASS = "V1:P V2:P V3:P V4:P Key:P V5:P V6:P"  # _summary(): code, then Passed / Failed / Skipped


@dataclass(frozen=True)
class Published:
    """What the owner put in storage and on-chain for one file, plus one requester's wrapped key."""

    ctx: FileContext
    dek: bytes
    encrypted: aead.EncryptedFile
    signed: signing.SignedManifest
    owner_sig_key: bytes
    wrapped_key: bytes

    @property
    def anchor(self) -> Anchor:
        return Anchor(
            context=self.ctx,
            ct_hash=self.encrypted.ct_hash,
            manifest_hash=self.signed.manifest.digest(),
            owner_sig_key=self.owner_sig_key,
        )


def _publish(owner: UserKeys, ctx: FileContext, dek: bytes, recipient: UserKeys, content: bytes = CONTENT) -> Published:
    """Encrypt, sign and wrap one file the way the owner's client does."""
    encrypted = aead.encrypt_file(dek, ctx, name=NAME, content=content, mime="text/plain")
    signed = signing.sign_manifest(owner.sig_key, signing.build_manifest(ctx, encrypted, created_at=1_760_000_000))
    return Published(
        ctx=ctx,
        dek=dek,
        encrypted=encrypted,
        signed=signed,
        owner_sig_key=owner.sig_public_key,
        wrapped_key=ecies.wrap_key(dek, recipient.enc_public_key, ctx, recipient.address),
    )


def _run(
    published: Published,
    recipient: UserKeys,
    *,
    obj: Fetched | None = None,
    manifest: Fetched | None = None,
    anchor: Anchor | None = None,
    wrapped_key: bytes | None = None,
    force: bool = False,
) -> RetrievedFile:
    """verify_and_decrypt on the honest inputs, except those overridden."""
    return verify_and_decrypt(
        anchor or published.anchor,
        obj or Fetched(published.encrypted.object_bytes),
        manifest or Fetched(published.signed.to_bytes()),
        wrapped_key=published.wrapped_key if wrapped_key is None else wrapped_key,
        enc_key=recipient.enc_key,
        recipient=recipient.address,
        force_decrypt=force,
    )


def _summary(result: RetrievedFile) -> str:
    return " ".join(f"{r.check.code}:{r.outcome.value[0].upper()}" for r in result.report.results)


def _flip(data: bytes, index: int) -> bytes:
    return data[:index] + bytes([data[index] ^ 0x01]) + data[index + 1 :]


def _manifest_with(published: Published, **changes: object) -> bytes:
    """The stored manifest with some fields changed but the original signature kept."""
    fields = {**published.signed.manifest.to_dict(), **changes}
    return canonical_json({"manifest": fields, "signature": published.signed.signature.to_dict()})


@pytest.fixture
def published(alice: UserKeys, bob: UserKeys, ctx: FileContext, dek: bytes) -> Published:
    return _publish(alice, ctx, dek, bob)


class TestHappyPath:
    def test_all_checks_pass_and_content_matches(self, published: Published, bob: UserKeys) -> None:
        result = _run(published, bob)
        assert _summary(result) == ALL_PASS
        assert result.ok and result.report.ok
        assert result.plaintext is not None
        assert result.plaintext.content == CONTENT
        assert result.plaintext.header.name == NAME
        assert tuple(r.check for r in result.report.results) == tuple(Check)

    def test_details_never_contain_the_dek(self, published: Published, bob: UserKeys) -> None:
        result = _run(published, bob)
        text = " ".join(r.detail for r in result.report.results) + repr(result)
        assert published.dek.hex() not in text
        assert CONTENT.decode() not in text

    def test_owner_opens_own_copy(self, alice: UserKeys, ctx: FileContext, dek: bytes) -> None:
        own = _publish(alice, ctx, dek, alice)
        assert _run(own, alice).ok


class TestStorageTampering:
    def test_flipped_ciphertext_byte(self, published: Published, bob: UserKeys) -> None:
        tampered = Fetched(_flip(published.encrypted.object_bytes, 40))
        result = _run(published, bob, obj=tampered)
        assert _summary(result) == "V1:F V2:P V3:P V4:P Key:S V5:S V6:S"
        assert result.plaintext is None

    def test_forced_decrypt_hits_the_gcm_tag(self, published: Published, bob: UserKeys) -> None:
        tampered = Fetched(_flip(published.encrypted.object_bytes, 40))
        result = _run(published, bob, obj=tampered, force=True)
        assert _summary(result) == "V1:F V2:P V3:P V4:P Key:P V5:F V6:S"
        assert "authentication failed" in result.report.result(Check.V5_DECRYPT).detail
        assert result.plaintext is None

    def test_modified_pt_digest(self, published: Published, bob: UserKeys) -> None:
        manifest = Fetched(_manifest_with(published, ptDigest="00" * 32))
        result = _run(published, bob, manifest=manifest)
        assert _summary(result) == "V1:P V2:F V3:P V4:F Key:S V5:S V6:S"

    def test_forced_decrypt_fails_v6(self, published: Published, bob: UserKeys) -> None:
        manifest = Fetched(_manifest_with(published, ptDigest="00" * 32))
        result = _run(published, bob, manifest=manifest, force=True)
        assert _summary(result) == "V1:P V2:F V3:P V4:F Key:P V5:P V6:F"
        assert result.plaintext is None

    def test_attacker_re_signs_with_own_key(self, published: Published, bob: UserKeys, mallory: UserKeys) -> None:
        forged = dataclasses.replace(published.signed.manifest, pt_digest=b"\x00" * 32)
        resigned = signing.sign_manifest(mallory.sig_key, forged)
        result = _run(published, bob, manifest=Fetched(resigned.to_bytes()))
        assert _summary(result) == "V1:P V2:F V3:P V4:F Key:S V5:S V6:S"

    def test_re_signed_manifest_fails_v4_even_if_hash_matched(
        self, published: Published, bob: UserKeys, mallory: UserKeys
    ) -> None:
        """V4 alone: the signature is checked with the key from the chain, not with a key
        that comes with the manifest."""
        resigned = signing.sign_manifest(mallory.sig_key, published.signed.manifest)
        result = _run(published, bob, manifest=Fetched(resigned.to_bytes()))
        assert _summary(result) == "V1:P V2:P V3:P V4:F Key:S V5:S V6:S"

    def test_rollback_to_an_older_version(self, published: Published, bob: UserKeys) -> None:
        older = aead.encrypt_file(published.dek, published.ctx, name=NAME, content=b"draft v1")
        result = _run(published, bob, obj=Fetched(older.object_bytes))
        assert _summary(result).startswith("V1:F V2:P V3:P V4:P")

    def test_deleted_object(self, published: Published, bob: UserKeys) -> None:
        result = _run(published, bob, obj=Fetched(error="Encrypted object abc… is missing from storage"), force=True)
        assert _summary(result) == "V1:F V2:P V3:P V4:P Key:P V5:S V6:S"
        assert result.report.result(Check.V1_CT_HASH).detail.endswith("missing from storage")

    def test_deleted_manifest(self, published: Published, bob: UserKeys) -> None:
        result = _run(published, bob, manifest=Fetched(error="gone"))
        assert _summary(result) == "V1:P V2:F V3:S V4:S Key:S V5:S V6:S"

    @pytest.mark.parametrize("garbage", [b"", b"not json", b"{}", b'{"manifest": 1, "signature": 2}'])
    def test_unreadable_manifest(self, published: Published, bob: UserKeys, garbage: bytes) -> None:
        result = _run(published, bob, manifest=Fetched(garbage), force=True)
        assert _summary(result) == "V1:P V2:F V3:S V4:S Key:P V5:P V6:S"
        assert result.plaintext is None


class TestWrongContext:
    def test_V3_manifest_of_another_file(
        self, alice: UserKeys, bob: UserKeys, published: Published, ctx: FileContext
    ) -> None:
        """The on-chain record of file B points at file A's ciphertext and manifest:
        the hashes match (V1, V2) but the manifest names another fileId."""
        other_ctx = dataclasses.replace(ctx, file_id=compute_file_id(alice.address, b"\x09" * 32))
        anchor = dataclasses.replace(published.anchor, context=other_ctx)
        wrapped = ecies.wrap_key(published.dek, bob.enc_public_key, other_ctx, bob.address)
        result = _run(published, bob, anchor=anchor, wrapped_key=wrapped)
        assert _summary(result) == "V1:P V2:P V3:F V4:P Key:S V5:S V6:S"
        assert "fileId" in result.report.result(Check.V3_CONTEXT).detail

    def test_V3_manifest_from_another_chain(self, alice: UserKeys, bob: UserKeys, ctx: FileContext, dek: bytes) -> None:
        on_sepolia = _publish(alice, dataclasses.replace(ctx, chain_id=11155111), dek, bob)
        anchor = dataclasses.replace(on_sepolia.anchor, context=ctx)
        result = _run(on_sepolia, bob, anchor=anchor)
        assert result.report.result(Check.V3_CONTEXT).outcome is Outcome.FAILED
        assert "chainId" in result.report.result(Check.V3_CONTEXT).detail

    def test_someone_elses_wrapped_key(self, published: Published, mallory: UserKeys) -> None:
        """Mallory copies Bob's wrappedKey from the chain; her own key cannot open it."""
        result = _run(published, mallory)
        assert _summary(result) == "V1:P V2:P V3:P V4:P Key:F V5:S V6:S"

    def test_wrapped_key_of_another_file(
        self, alice: UserKeys, bob: UserKeys, published: Published, ctx: FileContext
    ) -> None:
        other_ctx = dataclasses.replace(ctx, file_id=compute_file_id(alice.address, b"\x09" * 32))
        other = _publish(alice, other_ctx, aead.generate_dek(), bob)
        result = _run(other, bob, wrapped_key=published.wrapped_key)
        assert _summary(result) == "V1:P V2:P V3:P V4:P Key:F V5:S V6:S"


class TestOwnerKeys:
    def test_owner_without_signing_key(self, published: Published, bob: UserKeys) -> None:
        anchor = dataclasses.replace(published.anchor, owner_sig_key=b"")
        result = _run(published, bob, anchor=anchor)
        assert result.report.result(Check.V4_SIGNATURE).outcome is Outcome.FAILED

    def test_owner_key_not_on_the_curve(self, published: Published, bob: UserKeys) -> None:
        anchor = dataclasses.replace(published.anchor, owner_sig_key=b"\x02" + b"\xff" * 32)
        result = _run(published, bob, anchor=anchor)
        assert "unusable" in result.report.result(Check.V4_SIGNATURE).detail

    def test_V6_owner_signed_a_different_plaintext(self, alice: UserKeys, bob: UserKeys, published: Published) -> None:
        """A dishonest owner signs one ptDigest but encrypts other content; V1-V5 all pass."""
        lying = dataclasses.replace(published.signed.manifest, pt_digest=sha256(b"what I promised"))
        signed = signing.sign_manifest(alice.sig_key, lying)
        honest_looking = dataclasses.replace(published, signed=signed)
        result = _run(honest_looking, bob)
        assert _summary(result) == "V1:P V2:P V3:P V4:P Key:P V5:P V6:F"
        assert result.plaintext is None


class TestReport:
    def test_incomplete_report_is_not_ok(self) -> None:
        passed = tuple(CheckResult(c, Outcome.PASSED, "") for c in Check)
        assert VerificationReport(b"\x00" * 32, passed).ok
        assert not VerificationReport(b"\x00" * 32, passed[:-1]).ok
        assert not VerificationReport(b"\x00" * 32, passed[::-1]).ok

    def test_failures(self, published: Published, mallory: UserKeys) -> None:
        failures = _run(published, mallory).report.failures
        assert [r.check for r in failures] == [Check.UNWRAP]


class TestSavePlaintext:
    def test_saves_under_the_original_name(self, published: Published, bob: UserKeys, tmp_path: Path) -> None:
        path = save_plaintext(_run(published, bob), tmp_path)
        assert path == tmp_path / NAME
        assert path.read_bytes() == CONTENT

    def test_never_overwrites(self, published: Published, bob: UserKeys, tmp_path: Path) -> None:
        (tmp_path / NAME).write_bytes(b"mine")
        result = _run(published, bob)
        assert save_plaintext(result, tmp_path) == tmp_path / "report (1).txt"
        assert save_plaintext(result, tmp_path) == tmp_path / "report (2).txt"
        assert (tmp_path / NAME).read_bytes() == b"mine"

    def test_refuses_an_unverified_file(self, published: Published, mallory: UserKeys, tmp_path: Path) -> None:
        with pytest.raises(ServiceError, match="passed every check"):
            save_plaintext(_run(published, mallory), tmp_path)
        assert list(tmp_path.iterdir()) == []

    def test_windows_unsafe_characters_are_replaced(
        self, alice: UserKeys, bob: UserKeys, ctx: FileContext, dek: bytes, tmp_path: Path
    ) -> None:
        encrypted = aead.encrypt_file(dek, ctx, name='a:b*?"c.txt', content=b"x")
        signed = signing.sign_manifest(alice.sig_key, signing.build_manifest(ctx, encrypted))
        wrapped = ecies.wrap_key(dek, bob.enc_public_key, ctx, bob.address)
        published = Published(ctx, dek, encrypted, signed, alice.sig_public_key, wrapped)
        assert save_plaintext(_run(published, bob), tmp_path).name == "a_b___c.txt"

    def test_missing_directory(self, published: Published, bob: UserKeys, tmp_path: Path) -> None:
        with pytest.raises(ServiceError, match="Cannot save"):
            save_plaintext(_run(published, bob), tmp_path / "absent")
