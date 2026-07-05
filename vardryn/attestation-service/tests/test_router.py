"""
HTTP-layer integration tests for service/router.py — Week 6.

Exercises the FastAPI app via `fastapi.testclient.TestClient` (in-process,
no socket), covering all three endpoint groups end-to-end against a real
test Postgres instance:

  - registration:    POST /v1/credentials/register/{begin,complete}
  - signing ceremony: POST /v1/ceremonies/{begin,complete}
  - bundle export:    GET  /v1/tenants/{tenant_id}/ledger/{entry_id}/bundle

`get_countersigner` / `get_snapshot_archiver` / `get_rp_config` are
overridden via `app.dependency_overrides` with the same FakeKmsClient /
FakeSnapshotArchiver fakes used by tests/test_webauthn_ceremony.py and
tests/test_tamper_matrix.py (see router.py's module docstring note 1) —
neither google-cloud-kms, google-cloud-storage, nor a GCP project is needed.

The bundle returned by the GET endpoint is also fed through
verifier/verify_attestation.py as a subprocess — the same standalone CLI an
auditor would run — confirming the HTTP re-export round-trips cleanly
(0 FAIL; checks 10/11 SKIP because this entry has no tsa_token and is
seq=1 with no --prev-bundle).

Also covers the `_http_exception_for_ceremony_error` status-code mapping
(404 for an unknown credential_id) and the registration-challenge
single-use enforcement (409 on replay).

Run directly: `DATABASE_URL=postgresql+psycopg2://attestation_app:test@127.0.0.1/attestation_test python3 tests/test_router.py`
"""

from __future__ import annotations

import datetime
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from canonical.jcs import canonicalize  # noqa: E402
from service.kms_countersign import KmsCountersigner  # noqa: E402
from service.router import (  # noqa: E402
    RpConfig,
    app,
    get_countersigner,
    get_rp_config,
    get_snapshot_archiver,
)
from service.webauthn_primitives import b64url_encode  # noqa: E402

VERIFY_SCRIPT = ROOT / "verifier" / "verify_attestation.py"

RP_ID = "vardryn.example"
ORIGIN = "https://vardryn.example"
ALLOWLISTED_AAGUID = "cb69481e-8ff7-4039-93ec-0a2729a154a8"  # YubiKey 5 NFC

ACTION_BODY = {
    "decision": "approve",
    "control_id": "AC-2",
    "evidence_sha512": "deadbeefcafef00d",
    "statement": "Reviewed and approved per quarterly access review.",
}


# ── Fakes for KMS countersigning and WORM snapshot archival ─────────────────
# (same constructions as tests/test_webauthn_ceremony.py / test_tamper_matrix.py)


class FakeKmsClient:
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
    def __init__(self) -> None:
        self.stored: dict[str, bytes] = {}

    def archive(self, *, tenant_id: str, entry_id: str, snapshot_bytes: bytes) -> str:
        uri = f"gs://fake-bucket/{tenant_id}/{entry_id}/snapshot.html"
        self.stored[uri] = snapshot_bytes
        return uri

    def retrieve(self, uri: str) -> bytes:
        return self.stored[uri]


# ── Synthetic "packed" registration attestationObject ───────────────────────
# (same construction as tests/test_webauthn_registration.py)


def _aaguid_bytes(aaguid_str: str) -> bytes:
    return bytes.fromhex(aaguid_str.replace("-", ""))


def _self_signed_attestation_cert(attestation_key: ec.EllipticCurvePrivateKey, *, aaguid: bytes) -> bytes:
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Attestation Cert")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(attestation_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2040, 1, 1))
        .add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.45724.1.1.4"), b"\x04\x10" + aaguid),
            critical=False,
        )
        .sign(attestation_key, hashes.SHA256())
    )
    return cert.public_bytes(encoding=Encoding.DER)


def _build_registration_attestation_object(
    *,
    credential_id: bytes,
    credential_key: ec.EllipticCurvePrivateKey,
    attestation_key: ec.EllipticCurvePrivateKey,
    client_data_json: bytes,
    aaguid: bytes,
) -> bytes:
    pub_numbers = credential_key.public_key().public_numbers()
    cose_key = {
        1: 2,   # kty: EC2
        3: -7,  # alg: ES256
        -1: 1,  # crv: P-256
        -2: pub_numbers.x.to_bytes(32, "big"),
        -3: pub_numbers.y.to_bytes(32, "big"),
    }
    cose_key_cbor = cbor2.dumps(cose_key)

    rp_id_hash = hashlib.sha256(RP_ID.encode("utf-8")).digest()
    auth_data = (
        rp_id_hash
        + bytes([0x45])  # UP | UV | AT
        + struct.pack(">I", 0)
        + aaguid
        + struct.pack(">H", len(credential_id))
        + credential_id
        + cose_key_cbor
    )

    signed_message = auth_data + hashlib.sha256(client_data_json).digest()
    sig = attestation_key.sign(signed_message, ECDSA(hashes.SHA256()))

    cert_der = _self_signed_attestation_cert(attestation_key, aaguid=aaguid)
    att_stmt = {"alg": -7, "sig": sig, "x5c": [cert_der]}
    return cbor2.dumps({"fmt": "packed", "attStmt": att_stmt, "authData": auth_data})


def _build_client_data_json(*, type_: str, challenge_b64url: str, origin: str) -> bytes:
    return json.dumps(
        {"type": type_, "challenge": challenge_b64url, "origin": origin, "crossOrigin": False},
        separators=(",", ":"),
    ).encode("utf-8")


def _assertion_for(private_key: ec.EllipticCurvePrivateKey, challenge_b64url: str, counter: int):
    rp_id_hash = hashlib.sha256(RP_ID.encode("utf-8")).digest()
    auth_data = rp_id_hash + bytes([0x05]) + struct.pack(">I", counter)  # UP | UV
    client_data_json = _build_client_data_json(type_="webauthn.get", challenge_b64url=challenge_b64url, origin=ORIGIN)
    signed_message = auth_data + hashlib.sha256(client_data_json).digest()
    signature = private_key.sign(signed_message, ECDSA(hashes.SHA256()))
    return auth_data, client_data_json, signature


# ── verify_attestation.py subprocess runner ─────────────────────────────────


def _run_verifier(bundle: dict) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(bundle, f)
        bundle_path = Path(f.name)
    try:
        proc = subprocess.run(
            [sys.executable, str(VERIFY_SCRIPT), str(bundle_path)],
            capture_output=True,
            text=True,
        )
    finally:
        bundle_path.unlink()
    return proc.returncode, proc.stdout


# ── Test ─────────────────────────────────────────────────────────────────────


def test_full_http_flow(kms_key: rsa.RSAPrivateKey) -> None:
    archiver = FakeSnapshotArchiver()
    app.dependency_overrides[get_countersigner] = lambda: KmsCountersigner(
        client=FakeKmsClient(kms_key),
        key_version_name="projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
    )
    app.dependency_overrides[get_snapshot_archiver] = lambda: archiver
    app.dependency_overrides[get_rp_config] = lambda: RpConfig(rp_id=RP_ID, origin=ORIGIN)

    client = TestClient(app)

    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()

    # 1. Registration: begin -> a fresh single-use challenge.
    resp = client.post("/v1/credentials/register/begin")
    assert resp.status_code == 200, resp.text
    challenge_b64url = resp.json()["challenge_b64url"]

    # 2. Build a synthetic "packed" attestationObject binding that challenge
    #    to a fresh ES256 credential (the credential the ceremony will use).
    credential_key = ec.generate_private_key(ec.SECP256R1())
    attestation_key = ec.generate_private_key(ec.SECP256R1())
    credential_id_bytes = uuid.uuid4().bytes
    aaguid = _aaguid_bytes(ALLOWLISTED_AAGUID)

    client_data_json = _build_client_data_json(type_="webauthn.create", challenge_b64url=challenge_b64url, origin=ORIGIN)
    attestation_object = _build_registration_attestation_object(
        credential_id=credential_id_bytes,
        credential_key=credential_key,
        attestation_key=attestation_key,
        client_data_json=client_data_json,
        aaguid=aaguid,
    )

    # SCR-002: rp_id / origin are NOT sent by the client; the server verifies
    # against get_rp_config (overridden above to RP_ID / ORIGIN).
    registration_body = {
        "tenant_id": str(tenant_id),
        "user_id": str(user_id),
        "attestation_object_b64url": b64url_encode(attestation_object),
        "client_data_json_b64url": b64url_encode(client_data_json),
    }

    # 3. Registration: complete.
    resp = client.post("/v1/credentials/register/complete", json=registration_body)
    assert resp.status_code == 201, resp.text
    reg = resp.json()
    credential_id = reg["credential_id"]
    assert reg["aaguid"] == ALLOWLISTED_AAGUID
    assert reg["attestation_fmt"] == "packed"
    assert reg["allowlist_matched"] is True
    print("PASS: registration begin -> complete (server-authoritative origin/rpId, SCR-002)")

    # 4. Replaying the same (now-consumed) challenge is rejected with a coded error.
    resp = client.post("/v1/credentials/register/complete", json=registration_body)
    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"]["code"] == "ATT-1001", resp.text
    print("PASS: registration challenge replay rejected (409, ATT-1001)")

    # 5. Ceremony: begin.
    resp = client.post(
        "/v1/ceremonies/begin",
        json={
            "tenant_id": str(tenant_id),
            "user_id": str(user_id),
            "credential_id": credential_id,
            "action_type": "control.approve",
            "action_body": ACTION_BODY,
            "ial_record": "IAL2",
        },
    )
    assert resp.status_code == 200, resp.text
    begin = resp.json()
    assert begin["challenge_b64url"] == b64url_encode(hashlib.sha512(canonicalize(begin["payload"])).digest())
    print("PASS: ceremony begin")

    # 6. Sign the assertion with the just-registered credential's private key.
    auth_data, cdj, sig = _assertion_for(credential_key, begin["challenge_b64url"], counter=1)

    # 7. Ceremony: complete -> appends the ledger entry and returns a bundle.
    resp = client.post(
        "/v1/ceremonies/complete",
        json={
            "tenant_id": str(tenant_id),
            "challenge_b64url": begin["challenge_b64url"],
            "client_data_json_b64url": b64url_encode(cdj),
            "authenticator_data_b64url": b64url_encode(auth_data),
            "signature_b64url": b64url_encode(sig),
            # SCR-005: tsa_url is NOT a request field; it comes from server config.
        },
    )
    assert resp.status_code == 201, resp.text
    complete = resp.json()
    entry_id = complete["entry_id"]
    assert complete["seq"] == 1
    assert complete["bundle"]["schema"] == "vardryn.attestation.bundle/1.0"
    print("PASS: ceremony complete")

    # 8. Bundle export — re-fetches the entry + credential from Postgres and
    #    the snapshot bytes from the (fake) WORM archive, independently of
    #    the in-memory `bundle` returned by step 7.
    resp = client.get(f"/v1/tenants/{tenant_id}/ledger/{entry_id}/bundle")
    assert resp.status_code == 200, resp.text
    bundle = resp.json()
    assert bundle["schema"] == "vardryn.attestation.bundle/1.0"
    assert bundle["rp"] == {"id": RP_ID, "origin": ORIGIN}
    assert bundle["entry"]["entry_id"] == entry_id
    assert bundle["credential"]["credential_id"] == credential_id
    print("PASS: bundle export (GET .../ledger/{entry_id}/bundle)")

    # 9. The re-exported bundle round-trips cleanly through the standalone
    #    verifier — the same CLI an auditor would run.
    returncode, output = _run_verifier(bundle)
    assert returncode == 0, output
    assert "FAIL" not in output, output
    print("PASS: re-exported bundle verifies cleanly (0 FAIL) via verifier/verify_attestation.py")

    # 10. Bundle export for a nonexistent ledger entry -> 404 (ATT-3001).
    resp = client.get(f"/v1/tenants/{tenant_id}/ledger/{uuid.uuid4()}/bundle")
    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"]["code"] == "ATT-3001", resp.text
    print("PASS: bundle export for unknown entry_id -> 404 (ATT-3001)")

    # 11. Ceremony begin with an unknown credential_id -> 404 (ATT-2001).
    resp = client.post(
        "/v1/ceremonies/begin",
        json={
            "tenant_id": str(tenant_id),
            "user_id": str(user_id),
            "credential_id": "cred-does-not-exist",
            "action_type": "control.approve",
            "action_body": ACTION_BODY,
            "ial_record": "IAL2",
        },
    )
    assert resp.status_code == 404, resp.text
    assert resp.json()["detail"]["code"] == "ATT-2001", resp.text
    print("PASS: ceremony begin with unknown credential_id -> 404 (ATT-2001)")

    # 12. Health endpoint (liveness).
    resp = client.get("/health")
    assert resp.status_code == 200 and resp.json()["status"] == "ok", resp.text
    print("PASS: GET /health -> 200 ok")

    # 13. Oversized request body -> 413 (ATT-9001), rejected before parsing.
    huge = {
        "tenant_id": str(tenant_id),
        "user_id": str(user_id),
        "credential_id": credential_id,
        "action_type": "control.approve",
        "action_body": {"blob": "A" * (2 * 1024 * 1024)},  # ~2 MiB > 1 MiB limit
        "ial_record": "IAL2",
    }
    resp = client.post("/v1/ceremonies/begin", json=huge)
    assert resp.status_code == 413, resp.text
    assert resp.json()["detail"]["code"] == "ATT-9001", resp.text
    print("PASS: oversized request body -> 413 (ATT-9001)")

    # 14. action_body with a non-string value -> 400 (ATT-2008), strings-only invariant.
    resp = client.post(
        "/v1/ceremonies/begin",
        json={
            "tenant_id": str(tenant_id),
            "user_id": str(user_id),
            "credential_id": credential_id,
            "action_type": "control.approve",
            "action_body": {"decision": "approve", "amount": 1000000},  # int leaf -> rejected
            "ial_record": "IAL2",
        },
    )
    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"]["code"] == "ATT-2008", resp.text
    print("PASS: non-string action_body value -> 400 (ATT-2008)")

    app.dependency_overrides.clear()


if __name__ == "__main__":
    print("generating RSA-4096 fake-KMS test key (slow)...")
    kms_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    test_full_http_flow(kms_key)
    print("\nOK: all router tests passed")
