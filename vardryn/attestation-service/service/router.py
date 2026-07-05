"""
FastAPI HTTP surface — Week 6.

Wires together the pieces built in Weeks 1-4 into three endpoint groups:

  - `/v1/credentials/register/{begin,complete}` — enrolls a new hardware
    key (service/webauthn_registration.py).
  - `/v1/ceremonies/{begin,complete}` — the signing ceremony that appends a
    new `attestation_ledger` row (service/webauthn_ceremony.py).
  - `GET /v1/tenants/{tenant_id}/ledger/{entry_id}/bundle` — re-exports a
    previously-completed entry as a `vardryn.attestation.bundle/1.0`
    document (service/bundle.py), for handing to an auditor / the
    standalone verifier (verifier/verify_attestation.py).

ENGINEERING-CONFIDENCE NOTES (read before deploying):

1. Cloud KMS / GCS dependency injection: `get_countersigner()` and
   `get_snapshot_archiver()` construct REAL `KmsCountersigner` /
   `GcsSnapshotArchiver` instances from `google-cloud-kms` /
   `google-cloud-storage`. Neither package is installed in this dev
   environment (no GCP project is provisioned here — same caveat as
   service/kms_countersign.py and service/snapshot_archive.py), so these
   raise a clear 503 (ATT-4001 / ATT-4002, service/errors.py) at first use
   rather than an opaque `ImportError`. tests/test_router.py overrides both via
   `app.dependency_overrides` with the same FakeKmsClient /
   FakeSnapshotArchiver used by tests/test_webauthn_ceremony.py, so the
   HTTP layer itself IS exercised end-to-end — only the live-cloud wiring
   is unverified.

2. Registration challenges: `_RegistrationChallengeStore` is a
   process-local, in-memory, single-use+TTL store — NOT the
   `attestation_pending_challenges` pattern used by the signing ceremony
   (db/migrations/002), because that table's `signer_credential_id` is
   `NOT NULL` with a FK to `attestation_credentials`, and a credential being
   REGISTERED doesn't exist yet. This is a deliberate placeholder: it does
   not survive a process restart and does not work across multiple server
   instances. A production deployment needs a Postgres-backed registration
   challenge table before running more than one instance.

3. `rp_id` / `origin` for bundle re-export: `attestation_ledger` does not
   persist these per entry (service/webauthn_ceremony.py uses them only at
   completion time, to verify the assertion and build the response bundle).
   `get_rp_config()` therefore reads them from environment configuration,
   which assumes a single relying party (one web origin) for the whole
   deployment — consistent with this project's current single-RP design
   (§2.2). A multi-RP-per-tenant deployment would need a schema change to
   store these per entry.

4. `CeremonyError` (service/webauthn_ceremony.py) is not a typed exception
   hierarchy — see its module docstring. `_http_exception_for_ceremony_error`
   maps it to HTTP status codes by message content; `detail` always carries
   the full original message regardless of the mapped status code.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

import cbor2
from fastapi import APIRouter, Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError

from . import errors, models
from .bundle import build_bundle
from .db import tenant_session
from .entry_hash import ENTRY_HASH_FIELDS
from .kms_countersign import KmsCountersigner
from .snapshot_archive import GcsSnapshotArchiver, SnapshotArchiver
from .webauthn_ceremony import CeremonyError, begin_ceremony, complete_ceremony
from .webauthn_primitives import b64url_decode, b64url_encode, parse_client_data_json
from .webauthn_registration import RegistrationVerificationError, verify_registration

logger = logging.getLogger("vardryn.attestation")

# Reject request bodies larger than this before parsing (defense against
# resource-exhaustion via an oversized action_body / attestation object).
MAX_REQUEST_BODY_BYTES = 1 * 1024 * 1024  # 1 MiB

router = APIRouter()


# ── Dependencies ─────────────────────────────────────────────────────────────


def get_countersigner() -> KmsCountersigner:
    """Constructs a KmsCountersigner backed by a real Cloud KMS client.
    Reads `KMS_KEY_VERSION_NAME` (a full
    projects/.../cryptoKeyVersions/N resource name) from the environment.
    See module docstring note 1."""
    try:
        from google.cloud import kms_v1
    except ImportError as exc:
        raise errors.http_exception(
            errors.KMS_UNAVAILABLE,
            "google-cloud-kms is not installed; cannot construct a live KmsCountersigner.",
        ) from exc

    try:
        key_version_name = os.environ["KMS_KEY_VERSION_NAME"]
    except KeyError as exc:
        raise errors.http_exception(errors.KMS_UNAVAILABLE, "KMS_KEY_VERSION_NAME is not set.") from exc

    return KmsCountersigner(
        client=kms_v1.KeyManagementServiceClient(),
        key_version_name=key_version_name,
    )


def get_snapshot_archiver() -> SnapshotArchiver:
    """Constructs a GcsSnapshotArchiver backed by a real GCS client. Reads
    `SNAPSHOT_BUCKET_NAME` from the environment. See module docstring note 1."""
    try:
        from google.cloud import storage
    except ImportError as exc:
        raise errors.http_exception(
            errors.GCS_UNAVAILABLE,
            "google-cloud-storage is not installed; cannot construct a live GcsSnapshotArchiver.",
        ) from exc

    try:
        bucket_name = os.environ["SNAPSHOT_BUCKET_NAME"]
    except KeyError as exc:
        raise errors.http_exception(errors.GCS_UNAVAILABLE, "SNAPSHOT_BUCKET_NAME is not set.") from exc

    return GcsSnapshotArchiver(client=storage.Client(), bucket_name=bucket_name)


@dataclass(frozen=True)
class RpConfig:
    rp_id: str
    origin: str


def get_rp_config() -> RpConfig:
    """Server-authoritative relying-party identity (see module docstring note 3).
    Used at registration/ceremony COMPLETION to verify the WebAuthn origin/rpId
    against configuration the client cannot influence (SCR-002), and for bundle
    re-export."""
    try:
        return RpConfig(rp_id=os.environ["ATTESTATION_RP_ID"], origin=os.environ["ATTESTATION_ORIGIN"])
    except KeyError as exc:
        raise errors.http_exception(errors.RP_CONFIG_MISSING) from exc


def get_tsa_url() -> str | None:
    """Server-authoritative RFC 3161 TSA endpoint (SCR-005). Read from
    `ATTESTATION_TSA_URL` (optional; unset => no timestamp). The TSA URL is NOT
    accepted from the client: a client-supplied URL would be an authenticated
    SSRF sink (the server POSTs to it). Only https endpoints are honored."""
    url = os.environ.get("ATTESTATION_TSA_URL")
    if url and not url.lower().startswith("https://"):
        # Fail closed rather than POST to an unexpected scheme/host.
        logger.warning("ignoring non-https ATTESTATION_TSA_URL")
        return None
    return url or None


# ── Registration challenge store (see module docstring note 2) ─────────────


class RegistrationChallengeError(Exception):
    pass


_REGISTRATION_CHALLENGE_TTL = timedelta(seconds=120)


class _RegistrationChallengeStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._challenges: dict[str, datetime] = {}

    def issue(self) -> tuple[str, datetime]:
        challenge_b64url = b64url_encode(secrets.token_bytes(16))
        expires_at = datetime.now(timezone.utc) + _REGISTRATION_CHALLENGE_TTL
        with self._lock:
            self._challenges[challenge_b64url] = expires_at
        return challenge_b64url, expires_at

    def consume(self, challenge_b64url: str) -> None:
        with self._lock:
            expires_at = self._challenges.pop(challenge_b64url, None)
        if expires_at is None:
            raise RegistrationChallengeError(f"unknown or already-consumed challenge {challenge_b64url!r}")
        if datetime.now(timezone.utc) > expires_at:
            raise RegistrationChallengeError(f"challenge {challenge_b64url!r} has expired")


_registration_challenges = _RegistrationChallengeStore()


# ── Error mapping ────────────────────────────────────────────────────────────


def _http_exception_for_ceremony_error(exc: CeremonyError) -> HTTPException:
    """Maps a CeremonyError (untyped; see module docstring note 4) to a stable
    error code (service/errors.py). The full original message is always carried
    in the response detail regardless of the mapped code."""
    message = str(exc)
    if "unknown credential_id" in message:
        code = errors.CEREMONY_UNKNOWN_CREDENTIAL
    elif "does not belong to user" in message:
        code = errors.CEREMONY_CREDENTIAL_WRONG_USER
    elif "assertion verification failed" in message:
        code = errors.CEREMONY_ASSERTION_FAILED
    elif "signer credential" in message and "not found" in message:
        # Internal inconsistency (pending challenge references a missing
        # credential) — retrying a fresh ceremony cannot help (SCR-004).
        code = errors.CEREMONY_CREDENTIAL_MISSING
    elif "signCount" in message:
        code = errors.CEREMONY_SIGN_COUNT
    elif "chain advanced" in message:
        code = errors.CEREMONY_CHAIN_ADVANCED
    elif "consumed" in message or "expired" in message:
        code = errors.CEREMONY_CHALLENGE_INVALID
    else:
        code = errors.CEREMONY_CONFLICT
    return errors.http_exception(code, message)


# ── Registration ─────────────────────────────────────────────────────────────


class BeginRegistrationResponse(BaseModel):
    challenge_b64url: str
    expires_at: datetime


@router.post("/v1/credentials/register/begin", response_model=BeginRegistrationResponse)
def begin_registration() -> BeginRegistrationResponse:
    challenge_b64url, expires_at = _registration_challenges.issue()
    return BeginRegistrationResponse(challenge_b64url=challenge_b64url, expires_at=expires_at)


class CompleteRegistrationRequest(BaseModel):
    # NOTE (SCR-002): rp_id / origin are NOT accepted from the client. The
    # WebAuthn origin/rpId are verified against server-authoritative config
    # (get_rp_config), so a client cannot register a credential minted at a
    # phishing origin by declaring its own expected origin.
    tenant_id: UUID
    user_id: UUID
    attestation_object_b64url: str
    client_data_json_b64url: str


class CompleteRegistrationResponse(BaseModel):
    credential_id: str
    aaguid: str
    attestation_fmt: str
    allowlist_matched: bool


@router.post("/v1/credentials/register/complete", response_model=CompleteRegistrationResponse, status_code=201)
def complete_registration(
    req: CompleteRegistrationRequest,
    rp_config: RpConfig = Depends(get_rp_config),
) -> CompleteRegistrationResponse:
    client_data_json = b64url_decode(req.client_data_json_b64url)
    challenge_b64url = parse_client_data_json(client_data_json).get("challenge", "")

    try:
        _registration_challenges.consume(challenge_b64url)
    except RegistrationChallengeError as exc:
        raise errors.http_exception(errors.REG_CHALLENGE_INVALID, str(exc)) from exc

    try:
        result = verify_registration(
            attestation_object=b64url_decode(req.attestation_object_b64url),
            client_data_json=client_data_json,
            expected_challenge=b64url_decode(challenge_b64url),
            expected_origin=rp_config.origin,
            expected_rp_id=rp_config.rp_id,
        )
    except RegistrationVerificationError as exc:
        raise errors.http_exception(errors.REG_VERIFICATION_FAILED, str(exc)) from exc

    credential_id_str = b64url_encode(result.credential_id)

    try:
        with tenant_session(req.tenant_id) as session:
            session.add(
                models.AttestationCredential(
                    credential_id=credential_id_str,
                    user_id=req.user_id,
                    tenant_id=req.tenant_id,
                    public_key_cose=b64url_encode(cbor2.dumps(result.public_key_cose)),
                    aaguid=UUID(result.aaguid),
                    attestation_object=b64url_encode(result.attestation_object),
                    attestation_fmt=result.attestation_fmt,
                    mds_statement=None,
                    mds_snapshot_date=None,
                    allowlist_matched=result.allowlist_matched,
                    sign_count=0,
                    registered_at=datetime.now(timezone.utc),
                )
            )
    except IntegrityError as exc:
        raise errors.http_exception(
            errors.REG_CREDENTIAL_EXISTS, f"credential {credential_id_str!r} is already registered"
        ) from exc

    return CompleteRegistrationResponse(
        credential_id=credential_id_str,
        aaguid=result.aaguid,
        attestation_fmt=result.attestation_fmt,
        allowlist_matched=result.allowlist_matched,
    )


# ── Signing ceremony ─────────────────────────────────────────────────────────


class BeginCeremonyRequest(BaseModel):
    tenant_id: UUID
    user_id: UUID
    credential_id: str
    action_type: str
    action_body: dict
    ial_record: str


class BeginCeremonyResponse(BaseModel):
    challenge_b64url: str
    payload: dict
    snapshot_html: str
    expires_at: datetime


def _assert_action_body_strings_only(value: object, path: str = "action_body") -> None:
    """Enforce the strings-only signed-payload invariant at the API boundary
    (SCR-005 follow-on): reject numbers/bools/None leaves before they reach
    canonicalization (which would otherwise raise ValueError -> 500). Nested
    dicts/lists are allowed; every scalar leaf must be a str."""
    if isinstance(value, dict):
        for k, v in value.items():
            _assert_action_body_strings_only(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _assert_action_body_strings_only(v, f"{path}[{i}]")
    elif not isinstance(value, str):
        raise errors.http_exception(
            errors.CEREMONY_INVALID_ACTION_BODY,
            f"{path} is {type(value).__name__}; only string values are allowed (strings-only signed payload)",
        )


@router.post("/v1/ceremonies/begin", response_model=BeginCeremonyResponse)
def begin(req: BeginCeremonyRequest) -> BeginCeremonyResponse:
    _assert_action_body_strings_only(req.action_body)
    try:
        with tenant_session(req.tenant_id) as session:
            result = begin_ceremony(
                session=session,
                tenant_id=req.tenant_id,
                action_type=req.action_type,
                action_body=req.action_body,
                user_id=req.user_id,
                credential_id=req.credential_id,
                ial_record=req.ial_record,
            )
    except CeremonyError as exc:
        raise _http_exception_for_ceremony_error(exc) from exc

    return BeginCeremonyResponse(
        challenge_b64url=result.challenge_b64url,
        payload=result.payload,
        snapshot_html=result.snapshot_bytes.decode("utf-8"),
        expires_at=result.expires_at,
    )


class CompleteCeremonyRequest(BaseModel):
    # NOTE (SCR-002): rp_id / origin are verified against server config
    # (get_rp_config), not accepted from the client.
    # NOTE (SCR-005): tsa_url is NOT accepted from the client (it would be an
    # authenticated SSRF sink); it comes from server config (get_tsa_url).
    tenant_id: UUID
    challenge_b64url: str
    client_data_json_b64url: str
    authenticator_data_b64url: str
    signature_b64url: str


class CompleteCeremonyResponse(BaseModel):
    entry_id: UUID
    seq: int
    entry_hash: str
    snapshot_uri: str
    bundle: dict


@router.post("/v1/ceremonies/complete", response_model=CompleteCeremonyResponse, status_code=201)
def complete(
    req: CompleteCeremonyRequest,
    rp_config: RpConfig = Depends(get_rp_config),
    tsa_url: str | None = Depends(get_tsa_url),
    countersigner: KmsCountersigner = Depends(get_countersigner),
    archiver: SnapshotArchiver = Depends(get_snapshot_archiver),
) -> CompleteCeremonyResponse:
    try:
        with tenant_session(req.tenant_id) as session:
            result = complete_ceremony(
                session=session,
                tenant_id=req.tenant_id,
                challenge_b64url=req.challenge_b64url,
                client_data_json=b64url_decode(req.client_data_json_b64url),
                authenticator_data=b64url_decode(req.authenticator_data_b64url),
                signature=b64url_decode(req.signature_b64url),
                rp_id=rp_config.rp_id,
                origin=rp_config.origin,
                countersigner=countersigner,
                archiver=archiver,
                tsa_url=tsa_url,
            )
    except CeremonyError as exc:
        raise _http_exception_for_ceremony_error(exc) from exc

    entry = result.entry
    logger.info(
        "ceremony.complete",
        extra={"tenant_id": str(req.tenant_id), "entry_id": str(entry.entry_id), "seq": entry.seq},
    )
    return CompleteCeremonyResponse(
        entry_id=entry.entry_id,
        seq=entry.seq,
        entry_hash=entry.entry_hash,
        snapshot_uri=entry.snapshot_uri,
        bundle=result.bundle,
    )


# ── Bundle export ────────────────────────────────────────────────────────────


@router.get("/v1/tenants/{tenant_id}/ledger/{entry_id}/bundle")
def get_bundle(
    tenant_id: UUID,
    entry_id: UUID,
    rp_config: RpConfig = Depends(get_rp_config),
    archiver: SnapshotArchiver = Depends(get_snapshot_archiver),
) -> dict:
    with tenant_session(tenant_id) as session:
        entry = session.get(models.AttestationLedgerEntry, entry_id)
        if entry is None:
            raise errors.http_exception(errors.LEDGER_ENTRY_NOT_FOUND, f"ledger entry {entry_id} not found")

        credential = session.get(models.AttestationCredential, entry.signer_credential_id)
        if credential is None:
            raise errors.http_exception(
                errors.LEDGER_CREDENTIAL_NOT_FOUND, f"credential {entry.signer_credential_id!r} not found"
            )

        snapshot_bytes = archiver.retrieve(entry.snapshot_uri)

        canonical_fields: dict = {field: getattr(entry, field) for field in ENTRY_HASH_FIELDS}
        for field in ("entry_id", "tenant_id", "signer_user_id"):
            canonical_fields[field] = str(canonical_fields[field])

        bundle = build_bundle(
            entry={
                **canonical_fields,
                "platform_sigs": entry.platform_sigs,
                "tsa_token": entry.tsa_token,
                "created_at": entry.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
            payload=json.loads(entry.payload_jcs),
            payload_jcs=entry.payload_jcs.encode("utf-8"),
            snapshot_bytes=snapshot_bytes,
            snapshot_uri=entry.snapshot_uri,
            credential={
                "credential_id": credential.credential_id,
                "public_key_cose": credential.public_key_cose,
                "aaguid": str(credential.aaguid),
                "attestation_fmt": credential.attestation_fmt,
            },
            rp_id=rp_config.rp_id,
            origin=rp_config.origin,
        )

    return bundle


# ── Health ───────────────────────────────────────────────────────────────────


@router.get("/health")
def health() -> dict:
    """Liveness probe. Does NOT check KMS/GCS/DB reachability (those surface as
    per-request 503s, ATT-4001/4002) — it only confirms the process is up."""
    return {"status": "ok", "service": "vardryn-attestation"}


# ── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(title="Vardryn Attestation Service")


@app.middleware("http")
async def _limit_request_body(request, call_next):
    """Reject oversized request bodies before they are parsed (413). Guards the
    unbounded `action_body` / attestation-object fields against resource
    exhaustion. Streaming/chunked requests without Content-Length are allowed
    through to the endpoint (the DB/pydantic layers still bound real usage)."""
    def _error(code: errors.ErrorCode, message: str) -> JSONResponse:
        # Same {"detail": {code, message}} envelope FastAPI uses for
        # HTTPException, so clients read body["detail"]["code"] everywhere.
        return JSONResponse(status_code=code.http_status, content={"detail": {"code": code.code, "message": message}})

    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            too_large = int(content_length) > MAX_REQUEST_BODY_BYTES
        except ValueError:
            return _error(errors.BAD_CONTENT_LENGTH, errors.BAD_CONTENT_LENGTH.summary)
        if too_large:
            return _error(errors.REQUEST_TOO_LARGE, f"request body exceeds {MAX_REQUEST_BODY_BYTES} bytes")
    return await call_next(request)


app.include_router(router)
