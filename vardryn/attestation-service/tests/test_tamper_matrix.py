"""
Tamper matrix — §5.3 (Week 5).

Generates two real, valid attestation bundles (seq=1, seq=2) via the actual
`begin_ceremony` / `complete_ceremony` flow against the live test Postgres
instance — same fakes as tests/test_webauthn_ceremony.py (FakeKmsClient,
FakeSnapshotArchiver). A SYNTHETIC-but-internally-consistent RFC 3161 token
(same construction as tests/test_tsa.py's `_build_synthetic_token`, repeated
here so this file runs standalone) is attached to bundle1's `entry.tsa_token`
so check 10 has something to verify in the baseline.

Both baseline bundles are confirmed to verify CLEANLY (0 FAIL) via
verifier/verify_attestation.py, run as a SUBPROCESS — i.e. exactly the
standalone CLI an auditor would invoke, with its stdout parsed for the
per-check `[STATUS] NN. ...` lines.

Every verifier invocation pins the legitimate platform key out-of-band via
`--platform-key <key_ref>=<pem>` (V09/V09b) — exactly as a real auditor would
supply the platform's published KMS public key. Without it, check 9 SKIPs
rather than trusting the bundle-embedded PEM (the root of SCR-001), and the
matrix asserts that SKIP behaviour explicitly.

Then 14 INDEPENDENT single-field mutations are applied — one per case — to
deep copies of the baseline bundles, and the mutated bundle is re-verified.
Each case asserts that its documented check number(s) are in the FAIL set
(other checks may incidentally also FAIL; that is not asserted against).
Together the 14 field mutations plus T25/T26 touch every one of the 12 checks
at least once:

  1.  bundle_schema             -> check  1 (bundle schema)
  2.  payload_action_body        -> check  2 (JCS round-trip)
  3.  payload_jcs                 -> checks 2, 3 (JCS round-trip, H derivation)
  4.  entry_payload_hash          -> checks 3, 5, 9 (H, clientData.challenge, entry_hash)
  5.  snapshot_bytes              -> check  4 (snapshot hash / WYSIWYS)
  6.  entry_snapshot_hash         -> checks 4, 9
  7.  client_data_challenge       -> checks 5, 7, 9 (clientData, signature, entry_hash)
  8.  auth_data_uv_flag           -> checks 6, 7, 9 (UV flag, signature, entry_hash)
  9.  webauthn_signature          -> checks 7, 9
  10. credential_public_key       -> check  7 (signature vs. wrong key)
  11. credential_aaguid           -> check  8 (authenticator allowlist)
  12. platform_sig                -> check  9 (countersignature)
  13. tsa_token                   -> check 10 (RFC 3161 timestamp)
  14. chain_linkage_prev_entry_hash -> checks 9, 11 (chain linkage, bundle2 + --prev-bundle bundle1)
  T25 resign_attack             -> check  9 (V09 pinned-key mismatch; SCR-001)
  T26 entry_payload_mismatch    -> check 12 (V12b entry↔payload binding; V09 PASSES; SCR-001)

Finally, `test_vendored_modules_byte_identical` checks the byte-identical
vendoring promise made in the docstrings of canonical/jcs.py,
service/webauthn_primitives.py, service/entry_hash.py,
service/platform_signature.py and service/authenticator_allowlist.py: each
has a copy under verifier/ that must be byte-for-byte identical to its
service/ (or canonical/) counterpart.

Run directly: `DATABASE_URL=postgresql+psycopg2://attestation_app:test@127.0.0.1/attestation_test python3 tests/test_tamper_matrix.py`
"""

from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import json
import re
import struct
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace

import cbor2
from asn1crypto import algos, cms, tsp
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from service import models  # noqa: E402
from service.bundle import bundle_to_json_bytes  # noqa: E402
from service.db import tenant_session  # noqa: E402
from service.entry_hash import ENTRY_HASH_FIELDS, compute_entry_hash  # noqa: E402
from service.kms_countersign import KmsCountersigner  # noqa: E402
from service.webauthn_ceremony import begin_ceremony, complete_ceremony  # noqa: E402
from service.webauthn_primitives import b64url_decode, b64url_encode  # noqa: E402

VERIFY_SCRIPT = ROOT / "verifier" / "verify_attestation.py"

# The fake-KMS key_version_name used by _generate_bundles' countersigner —
# also the `key_ref` the verifier pins the trusted platform key under (V09b).
PLATFORM_KEY_REF = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

RP_ID = "vardryn.example"
ORIGIN = "https://vardryn.example"

ACTION_BODY = {
    "decision": "approve",
    "control_id": "AC-2",
    "evidence_sha512": "deadbeefcafef00d",
    "statement": "Reviewed and approved per quarterly access review.",
}

_VENDORED_PAIRS = (
    ("canonical/jcs.py", "verifier/canonical/jcs.py"),
    ("service/webauthn_primitives.py", "verifier/webauthn_primitives.py"),
    ("service/entry_hash.py", "verifier/entry_hash.py"),
    ("service/platform_signature.py", "verifier/platform_signature.py"),
    ("service/authenticator_allowlist.py", "verifier/authenticator_allowlist.py"),
)


# ── Synthetic credential / assertion / fake-infra helpers ───────────────────
# (same constructions as tests/test_webauthn_ceremony.py — repeated here so
# this file runs standalone.)


def _generate_credential() -> tuple[ec.EllipticCurvePrivateKey, str]:
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


def _register_credential(tenant_id: uuid.UUID, credential_id: str, user_id: uuid.UUID, public_key_cose: str) -> None:
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
                registered_at=dt.datetime.now(dt.timezone.utc),
            )
        )


def _assertion_for(private_key: ec.EllipticCurvePrivateKey, challenge_b64url: str, counter: int):
    rp_id_hash = hashlib.sha256(RP_ID.encode("utf-8")).digest()
    auth_data = rp_id_hash + bytes([0x05]) + struct.pack(">I", counter)  # UP | UV
    client_data_json = json.dumps(
        {"type": "webauthn.get", "challenge": challenge_b64url, "origin": ORIGIN, "crossOrigin": False},
        separators=(",", ":"),
    ).encode("utf-8")
    signed_message = auth_data + hashlib.sha256(client_data_json).digest()
    signature = private_key.sign(signed_message, ECDSA(hashes.SHA256()))
    return auth_data, client_data_json, signature


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


def _run_ceremony(tenant_id, user_id, credential_id, private_key, countersigner, archiver, counter, control_id):
    with tenant_session(tenant_id) as session:
        begin = begin_ceremony(
            session=session,
            tenant_id=tenant_id,
            action_type="control.approve",
            action_body={**ACTION_BODY, "control_id": control_id},
            user_id=user_id,
            credential_id=credential_id,
            ial_record="IAL2",
        )
    auth_data, client_data_json, signature = _assertion_for(private_key, begin.challenge_b64url, counter)
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
    return result


def _recompute_entry_hash_from_bundle(entry: dict) -> bytes:
    canonical_fields = {field: entry[field] for field in ENTRY_HASH_FIELDS}
    return compute_entry_hash(canonical_fields)


# ── Synthetic RFC 3161 token (same construction as tests/test_tsa.py) ──────


def _build_synthetic_tsa_token(entry_hash: bytes, *, tamper_signature: bool = False) -> bytes:
    """Builds a SYNTHETIC RFC 3161 TimeStampResp whose messageImprint is
    `entry_hash` (sha512) and whose CMS SignerInfo is RSA-PSS-SHA256 over a
    self-signed cert, matched via IssuerAndSerialNumber — the same
    construction as tests/test_tsa.py's `_build_synthetic_token`, trimmed to
    only the `tamper_signature` knob this file needs."""
    tsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(tsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime(2020, 1, 1))
        .not_valid_after(dt.datetime(2040, 1, 1))
        .sign(tsa_key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    asn1_cert = asn1_x509.Certificate.load(cert_der)

    tst_info = tsp.TSTInfo({
        "version": "v1",
        "policy": "1.2.3.4.5.6.7",
        "message_imprint": tsp.MessageImprint({
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha512"}),
            "hashed_message": entry_hash,
        }),
        "serial_number": 1,
        "gen_time": dt.datetime.now(dt.timezone.utc),
        "ordering": False,
    })
    tst_info_der = tst_info.dump()

    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({"type": "content_type", "values": cms.SetOfContentType(["tst_info"])}),
        cms.CMSAttribute({
            "type": "message_digest",
            "values": cms.SetOfOctetString([hashlib.sha256(tst_info_der).digest()]),
        }),
    ])

    signed_bytes = signed_attrs.untag().dump()
    signature = tsa_key.sign(
        signed_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    if tamper_signature:
        signature = bytes([signature[0] ^ 0xFF]) + signature[1:]

    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({
            "issuer_and_serial_number": cms.IssuerAndSerialNumber({
                "issuer": asn1_cert.issuer,
                "serial_number": asn1_cert.serial_number,
            }),
        }),
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "signed_attrs": signed_attrs,
        "signature_algorithm": algos.SignedDigestAlgorithm({
            "algorithm": "rsassa_pss",
            "parameters": algos.RSASSAPSSParams({
                "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
                "mask_gen_algorithm": algos.MaskGenAlgorithm({
                    "algorithm": "mgf1",
                    "parameters": algos.DigestAlgorithm({"algorithm": "sha256"}),
                }),
                "salt_length": 32,
            }),
        }),
        "signature": signature,
    })

    signed_data = cms.SignedData({
        "version": "v3",
        "digest_algorithms": cms.DigestAlgorithms([algos.DigestAlgorithm({"algorithm": "sha256"})]),
        "encap_content_info": cms.EncapsulatedContentInfo({
            "content_type": "tst_info",
            "content": tst_info,
        }),
        "certificates": cms.CertificateSet([cms.CertificateChoices({"certificate": asn1_cert})]),
        "signer_infos": cms.SignerInfos([signer_info]),
    })

    content_info = cms.ContentInfo({"content_type": "signed_data", "content": signed_data})

    resp = tsp.TimeStampResp({
        "status": tsp.PKIStatusInfo({"status": "granted"}),
        "time_stamp_token": content_info,
    })
    return resp.dump()


# ── Baseline bundle generation ──────────────────────────────────────────────


def _generate_bundles(kms_key: rsa.RSAPrivateKey) -> tuple[dict, dict]:
    """Runs two real ceremonies for a fresh tenant/credential, producing
    bundle1 (seq=1) and bundle2 (seq=2, chained from bundle1). A valid
    synthetic RFC 3161 token (matching bundle1's entry_hash) is attached to
    bundle1's entry.tsa_token so check 10 is exercised (PASS) in the
    baseline."""
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    credential_id = f"cred-tamper-{uuid.uuid4()}"

    private_key, public_key_cose = _generate_credential()
    _register_credential(tenant_id, credential_id, user_id, public_key_cose)

    countersigner = KmsCountersigner(
        client=FakeKmsClient(kms_key),
        key_version_name=PLATFORM_KEY_REF,
    )
    archiver = FakeSnapshotArchiver()

    result1 = _run_ceremony(tenant_id, user_id, credential_id, private_key, countersigner, archiver, counter=1, control_id="AC-2")
    bundle1 = result1.bundle

    entry_hash1 = _recompute_entry_hash_from_bundle(bundle1["entry"])
    token_der = _build_synthetic_tsa_token(entry_hash1)
    bundle1["entry"]["tsa_token"] = base64.b64encode(token_der).decode("ascii")

    result2 = _run_ceremony(tenant_id, user_id, credential_id, private_key, countersigner, archiver, counter=2, control_id="AC-3")
    bundle2 = result2.bundle

    return bundle1, bundle2


# ── verify_attestation.py subprocess runner ─────────────────────────────────

_CHECK_LINE_RE = re.compile(r"^\[(PASS|FAIL|SKIP)\]\s*(\d+)\.")


def _run_verifier(
    bundle_path: Path,
    prev_bundle_path: Path | None = None,
    platform_key_arg: str | None = None,
) -> tuple[int, dict[int, str], str]:
    """Runs verifier/verify_attestation.py as a subprocess. Returns
    (returncode, {check_number: status}, stdout). `platform_key_arg` is a
    'KEY_REF=PATH' string pinning the trusted platform key (V09/V09b)."""
    cmd = [sys.executable, str(VERIFY_SCRIPT), str(bundle_path)]
    if prev_bundle_path is not None:
        cmd += ["--prev-bundle", str(prev_bundle_path)]
    if platform_key_arg is not None:
        cmd += ["--platform-key", platform_key_arg]
    proc = subprocess.run(cmd, capture_output=True, text=True)

    statuses: dict[int, str] = {}
    for line in proc.stdout.splitlines():
        m = _CHECK_LINE_RE.match(line)
        if m:
            statuses[int(m.group(2))] = m.group(1)

    return proc.returncode, statuses, proc.stdout


# ── Tamper mutations (one bundle field changed per case, nothing else) ─────


def _flip_b64url_byte(s: str) -> str:
    raw = bytearray(b64url_decode(s))
    raw[0] ^= 0xFF
    return b64url_encode(bytes(raw))


def _flip_b64_byte(s: str) -> str:
    raw = bytearray(base64.b64decode(s))
    raw[0] ^= 0xFF
    return base64.b64encode(bytes(raw)).decode("ascii")


def tamper_bundle_schema(bundle: dict) -> dict:
    b = copy.deepcopy(bundle)
    b["schema"] = "vardryn.attestation.bundle/0.9"
    return b


def tamper_payload_action_body(bundle: dict) -> dict:
    """Mutates payload.action_body without touching payload_jcs."""
    b = copy.deepcopy(bundle)
    b["payload"]["action_body"]["decision"] = "deny"
    return b


def tamper_payload_jcs(bundle: dict) -> dict:
    """Replaces payload_jcs with the canonicalization of a DIFFERENT
    (but well-formed) payload."""
    b = copy.deepcopy(bundle)
    from canonical.jcs import canonicalize  # local import: keeps top-level import list lean

    different_payload = copy.deepcopy(b["payload"])
    different_payload["action_body"]["decision"] = "deny"
    b["payload_jcs"] = canonicalize(different_payload).decode("utf-8")
    return b


def tamper_entry_payload_hash(bundle: dict) -> dict:
    b = copy.deepcopy(bundle)
    b["entry"]["payload_hash"] = _flip_b64url_byte(b["entry"]["payload_hash"])
    return b


def tamper_snapshot_bytes(bundle: dict) -> dict:
    b = copy.deepcopy(bundle)
    raw = bytearray(base64.b64decode(b["snapshot"]))
    raw[0] ^= 0xFF
    b["snapshot"] = base64.b64encode(bytes(raw)).decode("ascii")
    return b


def tamper_entry_snapshot_hash(bundle: dict) -> dict:
    b = copy.deepcopy(bundle)
    b["entry"]["snapshot_hash"] = _flip_b64url_byte(b["entry"]["snapshot_hash"])
    return b


def tamper_client_data_challenge(bundle: dict) -> dict:
    b = copy.deepcopy(bundle)
    client_data_json = b64url_decode(b["entry"]["webauthn_client_data"])
    client_data = json.loads(client_data_json.decode("utf-8"))
    client_data["challenge"] = _flip_b64url_byte(client_data["challenge"])
    new_cdj = json.dumps(client_data, separators=(",", ":")).encode("utf-8")
    b["entry"]["webauthn_client_data"] = b64url_encode(new_cdj)
    return b


def tamper_auth_data_uv_flag(bundle: dict) -> dict:
    b = copy.deepcopy(bundle)
    auth_data = bytearray(b64url_decode(b["entry"]["webauthn_auth_data"]))
    auth_data[32] &= ~0x04  # clear UV
    b["entry"]["webauthn_auth_data"] = b64url_encode(bytes(auth_data))
    return b


def tamper_webauthn_signature(bundle: dict) -> dict:
    b = copy.deepcopy(bundle)
    b["entry"]["webauthn_signature"] = _flip_b64url_byte(b["entry"]["webauthn_signature"])
    return b


def tamper_credential_public_key(bundle: dict) -> dict:
    b = copy.deepcopy(bundle)
    _other_private_key, other_public_cose = _generate_credential()
    b["credential"]["public_key_cose"] = other_public_cose
    return b


def tamper_credential_aaguid(bundle: dict) -> dict:
    b = copy.deepcopy(bundle)
    b["credential"]["aaguid"] = "00000000-0000-0000-0000-000000000000"
    return b


def tamper_platform_sig(bundle: dict) -> dict:
    b = copy.deepcopy(bundle)
    b["entry"]["platform_sigs"][0]["sig"] = _flip_b64_byte(b["entry"]["platform_sigs"][0]["sig"])
    return b


def tamper_tsa_token(bundle: dict) -> dict:
    """Replaces bundle1's valid synthetic tsa_token with one whose CMS
    signature has been tampered (messageImprint still matches entry_hash)."""
    b = copy.deepcopy(bundle)
    entry_hash = _recompute_entry_hash_from_bundle(b["entry"])
    tampered_der = _build_synthetic_tsa_token(entry_hash, tamper_signature=True)
    b["entry"]["tsa_token"] = base64.b64encode(tampered_der).decode("ascii")
    return b


def tamper_chain_linkage_prev_entry_hash(bundle2: dict) -> dict:
    """Mutates bundle2's prev_entry_hash so it no longer matches bundle1's
    recomputed entry_hash (bundle1 itself is passed unmodified as
    --prev-bundle)."""
    b = copy.deepcopy(bundle2)
    b["entry"]["prev_entry_hash"] = _flip_b64url_byte(b["entry"]["prev_entry_hash"])
    return b


# ── SCR-001 re-sign attacks (T25, T26) ──────────────────────────────────────


def _pem_of(key: rsa.RSAPrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _resign_entry(bundle: dict, signing_key: rsa.RSAPrivateKey) -> dict:
    """Recompute entry_hash from the (already-mutated) entry and overwrite
    platform_sigs[0].{sig, public_key_pem} with a fresh RSA-PSS-4096-SHA512
    countersignature under `signing_key` — i.e. the attacker (or platform)
    re-mints the countersignature over the tampered entry."""
    entry_hash = _recompute_entry_hash_from_bundle(bundle["entry"])
    sig = signing_key.sign(
        entry_hash,
        padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=hashes.SHA512().digest_size),
        hashes.SHA512(),
    )
    bundle["entry"]["platform_sigs"][0]["sig"] = base64.b64encode(sig).decode("ascii")
    bundle["entry"]["platform_sigs"][0]["public_key_pem"] = _pem_of(signing_key)
    return bundle


def tamper_t25_resign_attack(bundle1: dict) -> dict:
    """T25 (SCR-001): forge an entry-row field NOT covered by the payload
    (entry_id), then re-generate the countersignature with an ATTACKER-owned
    key and swap in the attacker's embedded PEM. Must FAIL V09 — the attacker's
    key is not the pinned platform key (embedded-PEM / pinned-key mismatch)."""
    b = copy.deepcopy(bundle1)
    b["entry"]["tsa_token"] = None  # isolate V09 (a stale TSA token would also FAIL check 10)
    b["entry"]["entry_id"] = str(uuid.uuid4())
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    return _resign_entry(b, attacker_key)


def tamper_t26_entry_payload_mismatch(bundle1: dict, kms_key: rsa.RSAPrivateKey) -> dict:
    """T26 (SCR-001): leave the payload + WebAuthn assertion intact; change only
    the ledger-row copy of tenant_id, then re-mint the countersignature with the
    LEGITIMATE platform key. V09 PASSES (validly countersigned by the pinned
    key) but V12b MUST FAIL — entry.tenant_id no longer equals payload.tenant_id."""
    b = copy.deepcopy(bundle1)
    b["entry"]["tsa_token"] = None
    b["entry"]["tenant_id"] = str(uuid.uuid4())
    return _resign_entry(b, kms_key)


# (case_name, mutate_fn, target ("bundle1" or "bundle2"), expected FAIL check numbers)
_TAMPER_CASES: tuple[tuple[str, callable, str, frozenset[int]], ...] = (
    ("bundle_schema", tamper_bundle_schema, "bundle1", frozenset({1})),
    ("payload_action_body", tamper_payload_action_body, "bundle1", frozenset({2})),
    ("payload_jcs", tamper_payload_jcs, "bundle1", frozenset({2, 3})),
    ("entry_payload_hash", tamper_entry_payload_hash, "bundle1", frozenset({3, 5, 9})),
    ("snapshot_bytes", tamper_snapshot_bytes, "bundle1", frozenset({4})),
    ("entry_snapshot_hash", tamper_entry_snapshot_hash, "bundle1", frozenset({4, 9})),
    ("client_data_challenge", tamper_client_data_challenge, "bundle1", frozenset({5, 7, 9})),
    ("auth_data_uv_flag", tamper_auth_data_uv_flag, "bundle1", frozenset({6, 7, 9})),
    ("webauthn_signature", tamper_webauthn_signature, "bundle1", frozenset({7, 9})),
    ("credential_public_key", tamper_credential_public_key, "bundle1", frozenset({7})),
    ("credential_aaguid", tamper_credential_aaguid, "bundle1", frozenset({8})),
    ("platform_sig", tamper_platform_sig, "bundle1", frozenset({9})),
    ("tsa_token", tamper_tsa_token, "bundle1", frozenset({10})),
    ("chain_linkage_prev_entry_hash", tamper_chain_linkage_prev_entry_hash, "bundle2", frozenset({9, 11})),
)

assert len(_TAMPER_CASES) == 14


# ── Tests ────────────────────────────────────────────────────────────────────


def test_vendored_modules_byte_identical() -> None:
    for service_rel, verifier_rel in _VENDORED_PAIRS:
        service_bytes = (ROOT / service_rel).read_bytes()
        verifier_bytes = (ROOT / verifier_rel).read_bytes()
        assert service_bytes == verifier_bytes, f"{service_rel} and {verifier_rel} are NOT byte-identical"
    print(f"PASS: {len(_VENDORED_PAIRS)} vendored module pairs are byte-identical")


def test_tamper_matrix(kms_key: rsa.RSAPrivateKey) -> None:
    bundle1, bundle2 = _generate_bundles(kms_key)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        bundle1_path = tmp / "bundle1.json"
        bundle2_path = tmp / "bundle2.json"
        bundle1_path.write_bytes(bundle_to_json_bytes(bundle1))
        bundle2_path.write_bytes(bundle_to_json_bytes(bundle2))

        # Pin the legitimate platform key out-of-band (V09/V09b) — every
        # verifier invocation runs as a real auditor would, with the platform's
        # published KMS public key supplied via --platform-key.
        key_pem_path = tmp / "platform_key.pem"
        key_pem_path.write_text(_pem_of(kms_key), encoding="ascii")
        pk = f"{PLATFORM_KEY_REF}={key_pem_path}"

        rc, statuses, out = _run_verifier(bundle1_path, platform_key_arg=pk)
        assert rc == 0 and "FAIL" not in statuses.values(), f"bundle1 baseline not clean:\n{out}"
        assert statuses.get(9) == "PASS", f"baseline check 9 should PASS with a pinned key, got {statuses.get(9)}\n{out}"
        assert statuses.get(12) == "PASS", f"baseline check 12 (V12b) should PASS:\n{out}"
        rc, statuses, out = _run_verifier(bundle2_path, bundle1_path, platform_key_arg=pk)
        assert rc == 0 and "FAIL" not in statuses.values(), f"bundle2 baseline not clean:\n{out}"
        print("PASS: baseline bundles verify cleanly with pinned platform key (0 FAIL, checks 9 & 12 PASS)")

        # V09b: with NO pinned key, check 9 must SKIP (never trust the embedded
        # PEM) rather than PASS — the root of SCR-001.
        rc, statuses, out = _run_verifier(bundle1_path)
        assert statuses.get(9) == "SKIP", f"check 9 must SKIP without --platform-key, got {statuses.get(9)}\n{out}"
        print("PASS: without a pinned key, check 9 SKIPs (embedded PEM never trusted — V09b)")

        for name, mutate, target, expected_fail in _TAMPER_CASES:
            base = bundle1 if target == "bundle1" else bundle2
            tampered = mutate(base)
            tampered_path = tmp / f"tampered_{name}.json"
            tampered_path.write_bytes(bundle_to_json_bytes(tampered))

            prev = bundle1_path if target == "bundle2" else None
            rc, statuses, out = _run_verifier(tampered_path, prev, platform_key_arg=pk)

            assert rc == 1, f"{name}: expected nonzero exit (>=1 FAIL), got rc={rc}\n{out}"
            failed = {n for n, s in statuses.items() if s == "FAIL"}
            assert expected_fail <= failed, (
                f"{name}: expected checks {sorted(expected_fail)} to FAIL, "
                f"but FAIL set was {sorted(failed)}\n{out}"
            )
            print(f"PASS: {name} -> check(s) {sorted(expected_fail)} FAIL (full FAIL set: {sorted(failed)})")

        # ── T25 — re-sign attack (SCR-001): forge entry_id + attacker key ──
        t25_path = tmp / "tampered_T25_resign_attack.json"
        t25_path.write_bytes(bundle_to_json_bytes(tamper_t25_resign_attack(bundle1)))
        rc, statuses, out = _run_verifier(t25_path, platform_key_arg=pk)
        failed = {n for n, s in statuses.items() if s == "FAIL"}
        assert rc == 1 and 9 in failed, f"T25 must FAIL V09 (pinned-key mismatch); got rc={rc}, FAIL={sorted(failed)}\n{out}"
        print(f"PASS: T25 re-sign attack -> check 9 (V09) FAIL (full FAIL set: {sorted(failed)})")

        # ── T26 — entry↔payload mismatch (SCR-001): legit re-sign, bad identity ──
        t26_path = tmp / "tampered_T26_entry_payload_mismatch.json"
        t26_path.write_bytes(bundle_to_json_bytes(tamper_t26_entry_payload_mismatch(bundle1, kms_key)))
        rc, statuses, out = _run_verifier(t26_path, platform_key_arg=pk)
        failed = {n for n, s in statuses.items() if s == "FAIL"}
        assert rc == 1 and 12 in failed, f"T26 must FAIL V12b; got rc={rc}, FAIL={sorted(failed)}\n{out}"
        assert statuses.get(9) == "PASS", (
            f"T26: V09 must PASS (countersignature validly re-minted by the pinned key) so that V12b "
            f"is demonstrably the check that catches the identity mismatch; got check 9 = {statuses.get(9)}\n{out}"
        )
        print(f"PASS: T26 entry↔payload mismatch -> check 12 (V12b) FAIL, check 9 (V09) PASS (full FAIL set: {sorted(failed)})")

    total = len(_TAMPER_CASES) + 2
    print(f"\nOK: all {total} tamper cases produced their expected result(s) (14 field mutations + T25 + T26)")


if __name__ == "__main__":
    test_vendored_modules_byte_identical()

    print("generating RSA-4096 fake-KMS test key (slow)...")
    kms_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    test_tamper_matrix(kms_key)
    print("\nOK: all tamper matrix tests passed")
