"""
End-to-end integration tests for service/webauthn_ceremony.py against a real
Postgres instance (db/migrations/001 + 002 applied, connecting as the
`attestation_app` role — see tests/test_db_rls.py for why).

Builds a synthetic ES256 WebAuthn credential and assertions, a fake
`KmsCountersigner` (RSA-4096 key generated locally instead of calling Cloud
KMS — see service/kms_countersign.py's ENGINEERING-CONFIDENCE NOTE), and a
fake `SnapshotArchiver` (in-memory dict instead of GCS — see
service/snapshot_archive.py's ENGINEERING-CONFIDENCE NOTE).

Covers:
  - happy path: begin_ceremony -> complete_ceremony -> ledger row +
    attestation bundle, with entry_hash/payload_hash/snapshot_hash/
    platform_sigs all independently recomputed and re-verified from the
    bundle's contents (the same checks the offline verifier will perform).
  - challenge replay rejected (single-use enforcement).
  - signCount non-increase rejected (clone-detection).
  - stale chain tip rejected (a second ceremony that began before the first
    completed must be rejected once the chain has moved).

NOT covered: challenge expiry (`expires_at > now()`). `begin_ceremony`
always sets `expires_at = now() + 120s` and `attestation_app` only has
column-level UPDATE on `consumed_at` (db/migrations/002), so producing an
already-expired row would require either a 120s sleep or a superuser
connection to backdate `expires_at` — neither done here.

Run directly: `DATABASE_URL=postgresql+psycopg2://attestation_app:test@127.0.0.1/attestation_test python3 tests/test_webauthn_ceremony.py`
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from canonical.jcs import canonicalize  # noqa: E402
from service import models  # noqa: E402
from service.db import tenant_session  # noqa: E402
from service.entry_hash import ENTRY_HASH_FIELDS, compute_entry_hash  # noqa: E402
from service.kms_countersign import KmsCountersigner  # noqa: E402
from service.payload import genesis_hash  # noqa: E402
from service.platform_signature import verify_platform_sig_entry  # noqa: E402
from service.webauthn_ceremony import CeremonyError, begin_ceremony, complete_ceremony  # noqa: E402
from service.webauthn_primitives import b64url_decode, b64url_encode  # noqa: E402

RP_ID = "vardryn.example"
ORIGIN = "https://vardryn.example"

ACTION_BODY = {
    "decision": "approve",
    "control_id": "AC-2",
    "evidence_sha512": "deadbeefcafef00d",
    "statement": "Reviewed and approved per quarterly access review.",
}


# ── Synthetic credential / assertion helpers ────────────────────────────────


def _generate_credential() -> tuple[ec.EllipticCurvePrivateKey, str]:
    """Returns (private_key, public_key_cose) — `public_key_cose` is the
    base64url(CBOR(COSE key)) format stored in attestation_credentials."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.public_key().public_numbers()
    cose_key = {
        1: 2,   # kty: EC2
        3: -7,  # alg: ES256
        -1: 1,  # crv: P-256
        -2: numbers.x.to_bytes(32, "big"),
        -3: numbers.y.to_bytes(32, "big"),
    }
    return private_key, b64url_encode(cbor2.dumps(cose_key))


def _register_credential(
    tenant_id: uuid.UUID, credential_id: str, user_id: uuid.UUID, public_key_cose: str
) -> None:
    with tenant_session(tenant_id) as session:
        session.add(
            models.AttestationCredential(
                credential_id=credential_id,
                user_id=user_id,
                tenant_id=tenant_id,
                public_key_cose=public_key_cose,
                aaguid=uuid.UUID("cb69481e-8ff7-4039-93ec-0a2729a154a8"),
                attestation_object="deadbeef",
                attestation_fmt="packed",
                mds_statement=None,
                mds_snapshot_date=None,
                allowlist_matched=True,
                sign_count=0,
                registered_at=datetime.now(timezone.utc),
            )
        )


def _build_authenticator_data(*, flags: int, counter: int) -> bytes:
    rp_id_hash = hashlib.sha256(RP_ID.encode("utf-8")).digest()
    return rp_id_hash + bytes([flags]) + struct.pack(">I", counter)


def _build_client_data_json(*, challenge_b64url: str) -> bytes:
    return json.dumps(
        {"type": "webauthn.get", "challenge": challenge_b64url, "origin": ORIGIN, "crossOrigin": False},
        separators=(",", ":"),
    ).encode("utf-8")


def _sign_assertion(private_key: ec.EllipticCurvePrivateKey, auth_data: bytes, client_data_json: bytes) -> bytes:
    signed_message = auth_data + hashlib.sha256(client_data_json).digest()
    return private_key.sign(signed_message, ECDSA(hashes.SHA256()))


def _assertion_for(private_key: ec.EllipticCurvePrivateKey, challenge_b64url: str, counter: int):
    auth_data = _build_authenticator_data(flags=0x05, counter=counter)  # UP | UV
    client_data_json = _build_client_data_json(challenge_b64url=challenge_b64url)
    signature = _sign_assertion(private_key, auth_data, client_data_json)
    return auth_data, client_data_json, signature


# ── Fakes for KMS countersigning and WORM snapshot archival ─────────────────


class FakeKmsClient:
    """Stands in for google.cloud.kms_v1.KeyManagementServiceClient — see
    service/kms_countersign.py's ENGINEERING-CONFIDENCE NOTE."""

    def __init__(self, key: rsa.RSAPrivateKey):
        self._key = key

    def get_public_key(self, request: dict) -> SimpleNamespace:
        pem = self._key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        return SimpleNamespace(pem=pem)

    def asymmetric_sign(self, request: dict) -> SimpleNamespace:
        digest = request["digest"]["sha512"]
        sig = self._key.sign(
            digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=hashes.SHA512().digest_size),
            hashes.SHA512(),
        )
        return SimpleNamespace(signature=sig, verified_digest_crc32c=True)


class FakeSnapshotArchiver:
    """Stands in for service/snapshot_archive.py's GcsSnapshotArchiver — see
    its ENGINEERING-CONFIDENCE NOTE."""

    def __init__(self) -> None:
        self.stored: dict[str, bytes] = {}

    def archive(self, *, tenant_id: str, entry_id: str, snapshot_bytes: bytes) -> str:
        uri = f"gs://fake-bucket/{tenant_id}/{entry_id}/snapshot.html"
        self.stored[uri] = snapshot_bytes
        return uri

    def retrieve(self, uri: str) -> bytes:
        return self.stored[uri]


def _recompute_entry_hash(entry: models.AttestationLedgerEntry) -> bytes:
    """Recomputes entry_hash from the persisted row exactly as
    tests/test_webauthn_ceremony.py's complete_ceremony() did, and as the
    offline verifier (Week 4) will from the bundle's `entry` object."""
    uuid_fields = {"entry_id", "tenant_id", "signer_user_id"}
    fields = {
        field: (str(getattr(entry, field)) if field in uuid_fields else getattr(entry, field))
        for field in ENTRY_HASH_FIELDS
    }
    return compute_entry_hash(fields)


# ── Tests ────────────────────────────────────────────────────────────────────


def test_full_ceremony_happy_path(kms_key: rsa.RSAPrivateKey) -> None:
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    credential_id = f"cred-happy-{uuid.uuid4()}"

    private_key, public_key_cose = _generate_credential()
    _register_credential(tenant_id, credential_id, user_id, public_key_cose)

    with tenant_session(tenant_id) as session:
        begin = begin_ceremony(
            session=session,
            tenant_id=tenant_id,
            action_type="control.approve",
            action_body=ACTION_BODY,
            user_id=user_id,
            credential_id=credential_id,
            ial_record="IAL2",
        )

    assert begin.challenge_b64url == b64url_encode(hashlib.sha512(canonicalize(begin.payload)).digest())
    assert begin.payload["prev_ledger_hash"] == b64url_encode(genesis_hash())

    auth_data, client_data_json, signature = _assertion_for(private_key, begin.challenge_b64url, counter=1)

    countersigner = KmsCountersigner(
        client=FakeKmsClient(kms_key),
        key_version_name="projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
    )
    archiver = FakeSnapshotArchiver()

    with tenant_session(tenant_id) as session:
        result = complete_ceremony(
            session=session,
            tenant_id=tenant_id,
            challenge_b64url=begin.challenge_b64url,
            client_data_json=client_data_json,
            authenticator_data=auth_data,
            signature=signature,
            rp_id=RP_ID,
            origin=ORIGIN,
            countersigner=countersigner,
            archiver=archiver,
            tsa_url=None,
        )

    entry = result.entry
    assert entry.seq == 1
    assert entry.prev_entry_hash == b64url_encode(genesis_hash())
    assert entry.payload_hash == begin.challenge_b64url
    assert entry.tsa_token is None  # tsa_url=None -> never attempted
    assert len(entry.platform_sigs) == 1

    # entry_hash, payload_hash and snapshot_hash are all independently
    # recomputable — exactly what the offline verifier will do.
    recomputed_entry_hash = _recompute_entry_hash(entry)
    assert b64url_encode(recomputed_entry_hash) == entry.entry_hash
    verify_platform_sig_entry(entry.platform_sigs[0], recomputed_entry_hash)

    assert entry.snapshot_hash == b64url_encode(hashlib.sha512(begin.snapshot_bytes).digest())
    assert archiver.stored[entry.snapshot_uri] == begin.snapshot_bytes

    # Bundle self-containment checks (§4).
    bundle = result.bundle
    assert bundle["schema"] == "vardryn.attestation.bundle/1.0"
    assert bundle["rp"] == {"id": RP_ID, "origin": ORIGIN}
    assert bundle["entry"]["entry_id"] == str(entry.entry_id)
    assert bundle["entry"]["payload_hash"] == begin.challenge_b64url
    assert bundle["payload"] == begin.payload
    assert canonicalize(bundle["payload"]).decode("utf-8") == bundle["payload_jcs"]
    assert base64.b64decode(bundle["snapshot"]) == begin.snapshot_bytes
    assert bundle["snapshot_uri"] == entry.snapshot_uri
    assert bundle["credential"]["credential_id"] == credential_id

    print("PASS: full ceremony happy path (begin -> complete -> bundle)")

    # Replay: the same challenge can never be consumed twice.
    try:
        with tenant_session(tenant_id) as session:
            complete_ceremony(
                session=session,
                tenant_id=tenant_id,
                challenge_b64url=begin.challenge_b64url,
                client_data_json=client_data_json,
                authenticator_data=auth_data,
                signature=signature,
                rp_id=RP_ID,
                origin=ORIGIN,
                countersigner=countersigner,
                archiver=archiver,
                tsa_url=None,
            )
    except CeremonyError as exc:
        assert "consumed" in str(exc) or "expired" in str(exc)
        print("PASS: challenge replay rejected")
        return
    raise AssertionError("expected replay of a consumed challenge to be rejected")


def test_sign_count_non_increase_rejected(kms_key: rsa.RSAPrivateKey) -> None:
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    credential_id = f"cred-signcount-{uuid.uuid4()}"

    private_key, public_key_cose = _generate_credential()
    _register_credential(tenant_id, credential_id, user_id, public_key_cose)

    countersigner = KmsCountersigner(
        client=FakeKmsClient(kms_key),
        key_version_name="projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
    )
    archiver = FakeSnapshotArchiver()

    # First ceremony: counter=5 (> stored 0) succeeds, sign_count -> 5.
    with tenant_session(tenant_id) as session:
        begin1 = begin_ceremony(
            session=session,
            tenant_id=tenant_id,
            action_type="control.approve",
            action_body=ACTION_BODY,
            user_id=user_id,
            credential_id=credential_id,
            ial_record="IAL2",
        )
    auth1, cdj1, sig1 = _assertion_for(private_key, begin1.challenge_b64url, counter=5)
    with tenant_session(tenant_id) as session:
        complete_ceremony(
            session=session,
            tenant_id=tenant_id,
            challenge_b64url=begin1.challenge_b64url,
            client_data_json=cdj1,
            authenticator_data=auth1,
            signature=sig1,
            rp_id=RP_ID,
            origin=ORIGIN,
            countersigner=countersigner,
            archiver=archiver,
            tsa_url=None,
        )

    # Second ceremony: counter=5 again (no increase) -> rejected.
    with tenant_session(tenant_id) as session:
        begin2 = begin_ceremony(
            session=session,
            tenant_id=tenant_id,
            action_type="control.approve",
            action_body=ACTION_BODY,
            user_id=user_id,
            credential_id=credential_id,
            ial_record="IAL2",
        )
    auth2, cdj2, sig2 = _assertion_for(private_key, begin2.challenge_b64url, counter=5)

    try:
        with tenant_session(tenant_id) as session:
            complete_ceremony(
                session=session,
                tenant_id=tenant_id,
                challenge_b64url=begin2.challenge_b64url,
                client_data_json=cdj2,
                authenticator_data=auth2,
                signature=sig2,
                rp_id=RP_ID,
                origin=ORIGIN,
                countersigner=countersigner,
                archiver=archiver,
                tsa_url=None,
            )
    except CeremonyError as exc:
        assert "signCount" in str(exc)
        print("PASS: signCount non-increase rejected")
        return
    raise AssertionError("expected a non-increasing signCount to be rejected")


def test_stale_chain_tip_rejected(kms_key: rsa.RSAPrivateKey) -> None:
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    credential_id = f"cred-stale-{uuid.uuid4()}"

    private_key, public_key_cose = _generate_credential()
    _register_credential(tenant_id, credential_id, user_id, public_key_cose)

    countersigner = KmsCountersigner(
        client=FakeKmsClient(kms_key),
        key_version_name="projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
    )
    archiver = FakeSnapshotArchiver()

    # Begin two ceremonies before completing either — both observe the
    # (empty) chain and commit to prev_ledger_hash = genesis.
    with tenant_session(tenant_id) as session:
        begin_a = begin_ceremony(
            session=session,
            tenant_id=tenant_id,
            action_type="control.approve",
            action_body={**ACTION_BODY, "control_id": "AC-2"},
            user_id=user_id,
            credential_id=credential_id,
            ial_record="IAL2",
        )
    with tenant_session(tenant_id) as session:
        begin_b = begin_ceremony(
            session=session,
            tenant_id=tenant_id,
            action_type="control.approve",
            action_body={**ACTION_BODY, "control_id": "AC-3"},
            user_id=user_id,
            credential_id=credential_id,
            ial_record="IAL2",
        )

    assert begin_a.payload["prev_ledger_hash"] == begin_b.payload["prev_ledger_hash"]

    # Complete B first — this advances the chain to seq=1.
    auth_b, cdj_b, sig_b = _assertion_for(private_key, begin_b.challenge_b64url, counter=1)
    with tenant_session(tenant_id) as session:
        complete_ceremony(
            session=session,
            tenant_id=tenant_id,
            challenge_b64url=begin_b.challenge_b64url,
            client_data_json=cdj_b,
            authenticator_data=auth_b,
            signature=sig_b,
            rp_id=RP_ID,
            origin=ORIGIN,
            countersigner=countersigner,
            archiver=archiver,
            tsa_url=None,
        )

    # Completing A now sees a chain tip that no longer matches the
    # prev_ledger_hash baked into A's signed payload -> rejected.
    auth_a, cdj_a, sig_a = _assertion_for(private_key, begin_a.challenge_b64url, counter=2)
    try:
        with tenant_session(tenant_id) as session:
            complete_ceremony(
                session=session,
                tenant_id=tenant_id,
                challenge_b64url=begin_a.challenge_b64url,
                client_data_json=cdj_a,
                authenticator_data=auth_a,
                signature=sig_a,
                rp_id=RP_ID,
                origin=ORIGIN,
                countersigner=countersigner,
                archiver=archiver,
                tsa_url=None,
            )
    except CeremonyError as exc:
        assert "chain advanced" in str(exc)
        print("PASS: stale chain tip rejected")
        return
    raise AssertionError("expected a stale prev_ledger_hash to be rejected")


if __name__ == "__main__":
    print("generating RSA-4096 fake-KMS test key (slow)...")
    kms_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    test_full_ceremony_happy_path(kms_key)
    test_sign_count_non_increase_rejected(kms_key)
    test_stale_chain_tip_rejected(kms_key)
    print("\nOK: all webauthn_ceremony tests passed")
