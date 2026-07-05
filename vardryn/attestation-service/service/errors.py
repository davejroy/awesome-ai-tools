"""
Stable error-code catalog for the Attestation Service HTTP surface.

Every error the API returns carries a stable machine-readable code
(`ATT-NNNN`) plus a human summary, so callers can branch on the code rather
than parse prose, and so operators/auditors have a fixed reference
(docs/ERROR_CODES.md). Codes never change meaning once published; new
conditions get new codes.

Numbering:
  ATT-1xxx  registration ceremony
  ATT-2xxx  signing ceremony
  ATT-3xxx  ledger / bundle export
  ATT-4xxx  platform backend / configuration
  ATT-9xxx  generic / unexpected

The standalone offline verifier (verifier/verify_attestation.py) uses a
SEPARATE code space (V01–V12, one per check) documented alongside these in
docs/ERROR_CODES.md; it shares no code with this module and has no runtime
dependency on it.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException


@dataclass(frozen=True)
class ErrorCode:
    code: str
    http_status: int
    summary: str


# ── Registration ceremony (1xxx) ─────────────────────────────────────────────
REG_CHALLENGE_INVALID = ErrorCode("ATT-1001", 409, "Registration challenge is unknown, already consumed, or expired")
REG_VERIFICATION_FAILED = ErrorCode("ATT-1002", 400, "WebAuthn registration (attestation) verification failed")
REG_CREDENTIAL_EXISTS = ErrorCode("ATT-1003", 409, "Credential is already registered")

# ── Signing ceremony (2xxx) ──────────────────────────────────────────────────
CEREMONY_UNKNOWN_CREDENTIAL = ErrorCode("ATT-2001", 404, "credential_id is not registered")
CEREMONY_CREDENTIAL_WRONG_USER = ErrorCode("ATT-2002", 403, "Credential does not belong to the specified user")
CEREMONY_ASSERTION_FAILED = ErrorCode("ATT-2003", 400, "WebAuthn assertion verification failed")
CEREMONY_CHALLENGE_INVALID = ErrorCode("ATT-2004", 409, "Ceremony challenge is unknown, already consumed, or expired")
CEREMONY_CHAIN_ADVANCED = ErrorCode("ATT-2005", 409, "Ledger chain advanced since begin; retry with a fresh ceremony")
CEREMONY_SIGN_COUNT = ErrorCode("ATT-2006", 409, "Authenticator signCount did not increase (possible cloned key)")
CEREMONY_CREDENTIAL_MISSING = ErrorCode("ATT-2007", 500, "Internal inconsistency: pending challenge references a missing credential")
CEREMONY_CONFLICT = ErrorCode("ATT-2000", 409, "Ceremony could not be completed; begin a fresh ceremony and retry")

# ── Ledger / bundle export (3xxx) ────────────────────────────────────────────
LEDGER_ENTRY_NOT_FOUND = ErrorCode("ATT-3001", 404, "Ledger entry not found")
LEDGER_CREDENTIAL_NOT_FOUND = ErrorCode("ATT-3002", 404, "Signing credential for ledger entry not found")

# ── Platform backend / configuration (4xxx) ──────────────────────────────────
KMS_UNAVAILABLE = ErrorCode("ATT-4001", 503, "Cloud KMS countersigning backend is not available")
GCS_UNAVAILABLE = ErrorCode("ATT-4002", 503, "Cloud Storage (WORM archive) backend is not available")
RP_CONFIG_MISSING = ErrorCode("ATT-4003", 500, "Relying-party configuration (ATTESTATION_RP_ID / ATTESTATION_ORIGIN) is not set")

# ── Generic (9xxx) ───────────────────────────────────────────────────────────
UNEXPECTED = ErrorCode("ATT-9000", 500, "Unexpected server error")


ALL_ERROR_CODES: tuple[ErrorCode, ...] = (
    REG_CHALLENGE_INVALID,
    REG_VERIFICATION_FAILED,
    REG_CREDENTIAL_EXISTS,
    CEREMONY_UNKNOWN_CREDENTIAL,
    CEREMONY_CREDENTIAL_WRONG_USER,
    CEREMONY_ASSERTION_FAILED,
    CEREMONY_CHALLENGE_INVALID,
    CEREMONY_CHAIN_ADVANCED,
    CEREMONY_SIGN_COUNT,
    CEREMONY_CREDENTIAL_MISSING,
    CEREMONY_CONFLICT,
    LEDGER_ENTRY_NOT_FOUND,
    LEDGER_CREDENTIAL_NOT_FOUND,
    KMS_UNAVAILABLE,
    GCS_UNAVAILABLE,
    RP_CONFIG_MISSING,
    UNEXPECTED,
)


def http_exception(error: ErrorCode, detail: str | None = None) -> HTTPException:
    """Builds an HTTPException whose body is {"code", "message"} — the code is
    stable (branch on it), the message is human-facing context."""
    return HTTPException(
        status_code=error.http_status,
        detail={"code": error.code, "message": detail or error.summary},
    )
