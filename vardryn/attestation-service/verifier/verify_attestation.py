#!/usr/bin/env python3
"""
Standalone, offline attestation bundle verifier — §5.1.

Given one `vardryn.attestation.bundle/1.0` JSON document (service/bundle.py),
runs 11 independent checks and prints a PASS/FAIL/SKIP report. Exits 0 only
if every check is PASS or SKIP; exits 1 if any check FAILs.

Dependencies: `cryptography`, `fido2` (pulls in `cbor2`), and stdlib — see
requirements.txt. `asn1crypto` is OPTIONAL: without it, check 10 (RFC 3161
timestamp) reports SKIP instead of verifying `tsa_token`.

Every cryptographic primitive used here (canonicalize, compute_entry_hash,
verify_cose_signature, verify_platform_sig_entry, the YubiKey 5 AAGUID
allowlist) is a file-identical copy of the corresponding module under
service/ — see each vendored module's docstring. This script imports ONLY
those vendored copies plus stdlib, so it can run with nothing but this
`verifier/` directory and a bundle file: no database, no network, no
service/ checkout required.

Usage:
    python3 verify_attestation.py BUNDLE.json [--prev-bundle PREV_BUNDLE.json]

`--prev-bundle` is the bundle for the ledger entry immediately preceding
this one (seq - 1) in the same tenant's chain. It is required for check 11
("chain linkage") to PASS for any entry with seq > 1; without it, check 11
reports SKIP for those entries (seq == 1 is checked against the published
genesis hash regardless).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from authenticator_allowlist import is_allowed_aaguid  # noqa: E402
from canonical.jcs import canonicalize  # noqa: E402
from entry_hash import ENTRY_HASH_FIELDS, compute_entry_hash  # noqa: E402
from platform_signature import PlatformSignatureError, verify_platform_sig_entry  # noqa: E402
from webauthn_primitives import (  # noqa: E402
    SignatureVerificationError,
    b64url_decode,
    b64url_encode,
    parse_authenticator_data,
    parse_client_data_json,
    verify_cose_signature,
)

try:
    from tsa_verify import TsaVerificationError, verify_timestamp_token

    _TSA_AVAILABLE = True
except ImportError:
    _TSA_AVAILABLE = False

import cbor2  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

BUNDLE_SCHEMA = "vardryn.attestation.bundle/1.0"

# Mirrors service/bundle.py's _ENTRY_FIELDS without importing bundle.py
# (bundle.py is assembly-only and not part of the vendored crypto set).
_ENTRY_FIELDS = ENTRY_HASH_FIELDS + ("platform_sigs", "tsa_token", "created_at")

# Must match service/payload.py's GENESIS_STRING — duplicated here (one
# constant + one hashlib call) rather than vendoring all of payload.py,
# which pulls in unrelated nonce/timestamp helpers and a relative import of
# webauthn_primitives that would conflict with this script's flat layout.
GENESIS_STRING = "vardryn.attestation.genesis/1.0"

# ── Resource limits (20e T22–T24: malformed / oversized input must produce a
# specific error code, never a crash or unbounded memory use) ────────────────
MAX_BUNDLE_BYTES = 16 * 1024 * 1024   # a bundle file (JSON + base64 snapshot)
MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024  # decoded confirmation-view HTML
MAX_TSA_TOKEN_BYTES = 256 * 1024      # decoded RFC 3161 token
MAX_PEM_BYTES = 64 * 1024             # a pinned platform-key PEM file

# Exit codes: 0 = all checks PASS/SKIP; 1 = at least one check FAIL;
# 2 = input/container error (could not even run the checks — T22/T23/T24).
EXIT_OK = 0
EXIT_CHECK_FAILED = 1
EXIT_INPUT_ERROR = 2


class VerifierInputError(Exception):
    """A container/input problem (unreadable, oversized, or non-JSON bundle) —
    reported as a named error with a one-line reason and EXIT_INPUT_ERROR,
    never a raw traceback."""


def _read_json_file(path: Path, *, max_bytes: int, label: str) -> dict:
    """Size-bounded, error-mapped JSON file load. Raises VerifierInputError
    (never an uncaught OSError/JSONDecodeError/RecursionError) on any problem."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise VerifierInputError(f"cannot stat {label} {path}: {exc}") from exc
    if size > max_bytes:
        raise VerifierInputError(
            f"{label} {path} is {size} bytes, exceeding the {max_bytes}-byte limit (possible resource-exhaustion input)"
        )
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise VerifierInputError(f"cannot read {label} {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise VerifierInputError(f"{label} {path} is not valid UTF-8: {exc}") from exc
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise VerifierInputError(f"{label} {path} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise VerifierInputError(f"{label} {path} must be a JSON object, got {type(value).__name__}")
    return value


def _bounded_b64decode(data: str, *, max_bytes: int, field: str, urlsafe: bool = False) -> bytes:
    """base64-decode with an output-size bound so an oversized field raises
    (caught by the per-check handler → FAIL) instead of exhausting memory."""
    # 4 base64 chars encode 3 bytes; bound the encoded length before decoding.
    if len(data) > (max_bytes // 3 + 1) * 4 + 4:
        raise ValueError(f"{field} exceeds the {max_bytes}-byte decoded-size limit")
    raw = (base64.urlsafe_b64decode if urlsafe else base64.b64decode)(data)
    if len(raw) > max_bytes:
        raise ValueError(f"{field} decoded to {len(raw)} bytes, exceeding the {max_bytes}-byte limit")
    return raw


@dataclass
class CheckResult:
    number: int
    name: str
    status: str  # "PASS" | "FAIL" | "SKIP"
    detail: str


def _genesis_hash_b64url() -> str:
    return b64url_encode(hashlib.sha512(GENESIS_STRING.encode("utf-8")).digest())


# ── Individual checks ────────────────────────────────────────────────────────


def check_01_schema(bundle: dict) -> tuple[str, str]:
    errors = []
    if bundle.get("schema") != BUNDLE_SCHEMA:
        errors.append(f"bundle schema={bundle.get('schema')!r}, expected {BUNDLE_SCHEMA!r}")

    entry = bundle.get("entry", {})
    missing = [f for f in _ENTRY_FIELDS if f not in entry]
    if missing:
        errors.append(f"entry missing fields: {missing}")

    if entry.get("payload_hash_alg") != "SHA-512":
        errors.append(f"entry.payload_hash_alg={entry.get('payload_hash_alg')!r}, expected 'SHA-512'")

    if errors:
        return "FAIL", "; ".join(errors)
    return "PASS", f"schema={BUNDLE_SCHEMA}, payload_hash_alg=SHA-512, all entry fields present"


def check_02_payload_canonicalization(bundle: dict) -> tuple[str, str]:
    payload = bundle["payload"]
    payload_jcs = bundle["payload_jcs"]

    recomputed = canonicalize(payload)
    expected = payload_jcs.encode("utf-8")

    if recomputed != expected:
        return (
            "FAIL",
            f"canonicalize(payload) ({len(recomputed)} bytes) != bundle.payload_jcs ({len(expected)} bytes)",
        )
    return "PASS", f"canonicalize(payload) is byte-identical to payload_jcs ({len(expected)} bytes)"


def check_03_payload_hash(bundle: dict) -> tuple[str, str]:
    payload_jcs = bundle["payload_jcs"]
    entry = bundle["entry"]

    computed = b64url_encode(hashlib.sha512(payload_jcs.encode("utf-8")).digest())
    claimed = entry["payload_hash"]

    if computed != claimed:
        return "FAIL", f"SHA-512(payload_jcs)={computed!r} != entry.payload_hash={claimed!r}"
    return "PASS", f"entry.payload_hash = SHA-512(payload_jcs) = {claimed} (= H, the WebAuthn challenge)"


def check_04_snapshot_hash(bundle: dict) -> tuple[str, str]:
    entry = bundle["entry"]
    payload = bundle["payload"]

    snapshot_bytes = _bounded_b64decode(bundle["snapshot"], max_bytes=MAX_SNAPSHOT_BYTES, field="snapshot")
    computed = b64url_encode(hashlib.sha512(snapshot_bytes).digest())

    if computed != entry["snapshot_hash"]:
        return "FAIL", f"SHA-512(snapshot bytes)={computed!r} != entry.snapshot_hash={entry['snapshot_hash']!r}"
    if computed != payload.get("snapshot_hash"):
        return (
            "FAIL",
            f"SHA-512(snapshot bytes)={computed!r} != payload.snapshot_hash={payload.get('snapshot_hash')!r} "
            "(the exported snapshot does not match what was committed in the signed payload)",
        )
    return "PASS", f"SHA-512(snapshot) = entry.snapshot_hash = payload.snapshot_hash = {computed}"


def check_05_client_data(bundle: dict) -> tuple[str, str]:
    entry = bundle["entry"]
    rp = bundle["rp"]

    client_data_json = b64url_decode(entry["webauthn_client_data"])
    client_data = parse_client_data_json(client_data_json)

    errors = []
    if client_data.get("type") != "webauthn.get":
        errors.append(f"clientData.type={client_data.get('type')!r}, expected 'webauthn.get'")
    if client_data.get("challenge") != entry["payload_hash"]:
        errors.append(
            f"clientData.challenge={client_data.get('challenge')!r} != entry.payload_hash={entry['payload_hash']!r}"
        )
    if client_data.get("origin") != rp["origin"]:
        errors.append(f"clientData.origin={client_data.get('origin')!r} != rp.origin={rp['origin']!r}")

    if errors:
        return "FAIL", "; ".join(errors)
    return "PASS", f"type=webauthn.get, challenge=entry.payload_hash, origin={rp['origin']}"


def check_06_authenticator_data(bundle: dict) -> tuple[str, str]:
    entry = bundle["entry"]
    rp = bundle["rp"]

    auth_data_bytes = b64url_decode(entry["webauthn_auth_data"])
    auth_data = parse_authenticator_data(auth_data_bytes)

    expected_rp_id_hash = hashlib.sha256(rp["id"].encode("utf-8")).digest()

    errors = []
    if auth_data.rp_id_hash != expected_rp_id_hash:
        errors.append("authData.rpIdHash != SHA-256(rp.id)")
    if not auth_data.user_present:
        errors.append("authData UP (user present) flag is not set")
    if not auth_data.user_verified:
        errors.append("authData UV (user verified) flag is not set")

    if errors:
        return "FAIL", "; ".join(errors)
    return "PASS", f"rpIdHash=SHA-256(rp.id), UP=1, UV=1, signCount={auth_data.counter}"


def check_07_signature(bundle: dict) -> tuple[str, str]:
    entry = bundle["entry"]
    credential = bundle["credential"]

    client_data_json = b64url_decode(entry["webauthn_client_data"])
    auth_data_bytes = b64url_decode(entry["webauthn_auth_data"])
    signature = b64url_decode(entry["webauthn_signature"])

    cose_key = cbor2.loads(b64url_decode(credential["public_key_cose"]))
    signed_message = auth_data_bytes + hashlib.sha256(client_data_json).digest()

    try:
        verify_cose_signature(cose_key, signed_message, signature)
    except SignatureVerificationError as exc:
        return "FAIL", f"webauthn_signature does not verify against credential's registered key: {exc}"

    return "PASS", f"webauthn_signature verifies against credential {credential['credential_id']!r}'s registered COSE key"


def check_08_authenticator_allowlist(bundle: dict) -> tuple[str, str]:
    credential = bundle["credential"]
    aaguid = credential.get("aaguid", "")

    if is_allowed_aaguid(aaguid):
        return (
            "PASS",
            f"aaguid={aaguid} is on the YubiKey 5 allowlist — NOTE: allowlist is not yet "
            "cross-checked against a live FIDO MDS3 BLOB (see service/authenticator_allowlist.py)",
        )
    return "FAIL", f"aaguid={aaguid!r} is NOT on the YubiKey 5 allowlist (service/authenticator_allowlist.py)"


def _public_keys_match(pem_a: str, pem_b: str) -> bool:
    """True iff two PEM public keys encode the same key (compared by DER
    SubjectPublicKeyInfo, so whitespace/line-ending differences don't matter)."""
    try:
        der_a = serialization.load_pem_public_key(pem_a.encode("ascii")).public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        der_b = serialization.load_pem_public_key(pem_b.encode("ascii")).public_bytes(
            encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except Exception:
        return False
    return der_a == der_b


def check_09_entry_hash_and_countersignature(
    bundle: dict, trusted_platform_keys: dict[str, str] | None
) -> tuple[str, str]:
    """V09 / V09b (20d, patched v0.2 per SCR-001).

    The platform countersignature MUST be verified against a public key
    pinned OUT OF BAND (a trust store keyed by `key_ref` == `kms_key_version`),
    NOT the bundle-embedded PEM. The embedded PEM is advisory only: if it
    disagrees with the pinned key, that is a FAIL. An unknown `key_ref` is a
    FAIL (V09b — no trust-on-first-use). Verifying against the bundle-supplied
    key would be self-referential and defeat the check (the SCR-001 defect)."""
    entry = bundle["entry"]

    canonical_fields = {field: entry[field] for field in ENTRY_HASH_FIELDS}
    entry_hash = compute_entry_hash(canonical_fields)
    entry_hash_b64url = b64url_encode(entry_hash)

    platform_sigs = entry.get("platform_sigs") or []
    if not platform_sigs:
        return "FAIL", (
            f"entry_hash={entry_hash_b64url} recomputed, but platform_sigs is empty "
            "(V09 required-signature policy)"
        )

    # V09b: with no out-of-band trust anchor there is nothing to pin against.
    # Trusting the embedded PEM would be self-referential (SCR-001), so we do
    # NOT return PASS — we SKIP loudly. A real audit MUST supply --platform-key.
    if not trusted_platform_keys:
        return "SKIP", (
            f"entry_hash={entry_hash_b64url} recomputed, but no platform key was pinned "
            "(--platform-key <key_ref>=<pem>). Per V09b the bundle-embedded PEM is advisory "
            "ONLY and must not be trusted on its own, so platform provenance is UNVERIFIED. "
            "Re-run with the platform's out-of-band public key to complete this check."
        )

    verified_suites = []
    errors = []
    for i, sig in enumerate(platform_sigs):
        key_ref = sig.get("kms_key_version")
        trusted_pem = trusted_platform_keys.get(key_ref)
        if trusted_pem is None:
            errors.append(
                f"platform_sigs[{i}]: key_ref={key_ref!r} is not in the pinned trust store "
                "(V09b: unknown key_ref — no trust-on-first-use)"
            )
            continue
        embedded_pem = sig.get("public_key_pem")
        if embedded_pem is not None and not _public_keys_match(embedded_pem, trusted_pem):
            errors.append(
                f"platform_sigs[{i}]: bundle-embedded public_key_pem does not match the pinned key "
                f"for key_ref={key_ref!r} (V09: advisory PEM / pinned-key mismatch)"
            )
            continue
        # Verify against the PINNED key, not the embedded one.
        pinned_sig = {**sig, "public_key_pem": trusted_pem}
        try:
            verify_platform_sig_entry(pinned_sig, entry_hash)
            verified_suites.append(sig.get("suite", "?"))
        except PlatformSignatureError as exc:
            errors.append(
                f"platform_sigs[{i}] ({sig.get('suite', '?')}): {exc} "
                f"(verified against pinned key_ref={key_ref!r})"
            )

    if not verified_suites:
        return "FAIL", (
            f"entry_hash={entry_hash_b64url}; no platform_sigs entry verified against a pinned key: "
            f"{'; '.join(errors)}"
        )

    detail = (
        f"entry_hash={entry_hash_b64url} (recomputed); verified against pinned key(s), "
        f"suites: {', '.join(verified_suites)}"
    )
    if errors:
        detail += f"; additionally, unverified/unpinned entries present: {'; '.join(errors)}"
    return "PASS", detail


def check_12_entry_payload_binding(bundle: dict) -> tuple[str, str]:
    """V12b (20d, added v0.2 per SCR-001).

    Binds the ledger entry's identity fields to the HARDWARE-SIGNED payload,
    so the WebAuthn signature (which covers the payload, checks 3/5/7)
    transitively authorizes the entry-row identity. Without this, an attacker
    who can re-mint the platform countersignature could alter the entry-row
    identity fields undetected.

    Field-name mapping (this implementation predates the 20d naming): the spec
    says `signer_identity_id` / `payload.actor.identity_id`; here they are
    `signer_user_id` / `payload.actor.user_id`."""
    entry = bundle["entry"]
    payload = bundle["payload"]
    actor = payload.get("actor") or {}

    errors = []
    if entry.get("tenant_id") != payload.get("tenant_id"):
        errors.append(
            f"entry.tenant_id={entry.get('tenant_id')!r} != payload.tenant_id={payload.get('tenant_id')!r}"
        )
    if entry.get("signer_user_id") != actor.get("user_id"):
        errors.append(
            f"entry.signer_user_id={entry.get('signer_user_id')!r} != payload.actor.user_id={actor.get('user_id')!r}"
        )
    # Strengthening (still within I3/I4): also bind the signing credential.
    if entry.get("signer_credential_id") != actor.get("credential_id"):
        errors.append(
            f"entry.signer_credential_id={entry.get('signer_credential_id')!r} != "
            f"payload.actor.credential_id={actor.get('credential_id')!r}"
        )
    # entry.payload_hash MUST equal SHA-512(canonical payload) — ties H (the
    # WebAuthn challenge) into the same binding assertion.
    computed_h = b64url_encode(hashlib.sha512(bundle["payload_jcs"].encode("utf-8")).digest())
    if entry.get("payload_hash") != computed_h:
        errors.append(
            f"entry.payload_hash={entry.get('payload_hash')!r} != SHA-512(canonical payload)={computed_h!r}"
        )

    if errors:
        return "FAIL", "; ".join(errors) + " (V12b entry↔payload identity binding)"
    return "PASS", (
        "entry.{tenant_id, signer_user_id, signer_credential_id, payload_hash} are all bound to the "
        "hardware-signed payload (V12b)"
    )


def check_10_tsa_token(bundle: dict, entry_hash: bytes) -> tuple[str, str]:
    entry = bundle["entry"]
    tsa_token = entry.get("tsa_token")

    if tsa_token is None:
        return "SKIP", "entry.tsa_token is null (RFC 3161 timestamp is optional, §3)"

    if not _TSA_AVAILABLE:
        return "SKIP", "asn1crypto is not installed; cannot verify entry.tsa_token (optional dependency)"

    try:
        token_der = _bounded_b64decode(tsa_token, max_bytes=MAX_TSA_TOKEN_BYTES, field="tsa_token")
        result = verify_timestamp_token(token_der, entry_hash)
    except TsaVerificationError as exc:
        return "FAIL", f"tsa_token does not verify: {exc}"

    tsa_name = result.tsa_name or "(unnamed)"
    return "PASS", f"tsa_token verifies: gen_time={result.gen_time.isoformat()}, tsa={tsa_name}"


def check_11_chain_linkage(bundle: dict, prev_bundle: dict | None) -> tuple[str, str]:
    entry = bundle["entry"]
    seq = entry["seq"]
    prev_entry_hash = entry["prev_entry_hash"]

    if seq == 1:
        genesis = _genesis_hash_b64url()
        if prev_entry_hash != genesis:
            return "FAIL", f"seq=1 but prev_entry_hash={prev_entry_hash!r} != genesis hash {genesis!r}"
        return "PASS", f"seq=1, prev_entry_hash = genesis ({genesis})"

    if prev_bundle is None:
        return "SKIP", f"seq={seq} > 1 and no --prev-bundle provided; chain linkage not checked"

    prev_entry = prev_bundle["entry"]
    prev_canonical_fields = {field: prev_entry[field] for field in ENTRY_HASH_FIELDS}
    prev_entry_hash_recomputed = b64url_encode(compute_entry_hash(prev_canonical_fields))

    errors = []
    if prev_entry["seq"] + 1 != seq:
        errors.append(f"--prev-bundle entry.seq={prev_entry['seq']}, expected {seq - 1}")
    if prev_entry_hash != prev_entry_hash_recomputed:
        errors.append(
            f"entry.prev_entry_hash={prev_entry_hash!r} != recomputed hash of --prev-bundle "
            f"({prev_entry_hash_recomputed!r})"
        )

    if errors:
        return "FAIL", "; ".join(errors)
    return "PASS", f"seq={seq} immediately follows --prev-bundle (seq={prev_entry['seq']}) in the hash chain"


# ── Orchestration ────────────────────────────────────────────────────────────


_CHECKS = [
    ("Bundle schema and entry shape", check_01_schema),
    ("Payload canonicalization (JCS round-trip)", check_02_payload_canonicalization),
    ("Payload hash == WebAuthn challenge H", check_03_payload_hash),
    ("Snapshot hash matches entry and payload", check_04_snapshot_hash),
    ("clientDataJSON (type, challenge, origin)", check_05_client_data),
    ("authenticatorData (rpIdHash, UP, UV)", check_06_authenticator_data),
    ("WebAuthn assertion signature", check_07_signature),
    ("Authenticator allowlist (AAGUID)", check_08_authenticator_allowlist),
    ("entry_hash + platform countersignature (V09/V09b)", None),  # special-cased: needs pinned keys
    ("RFC 3161 timestamp (tsa_token)", None),  # special-cased: needs entry_hash
    ("Chain linkage (prev_entry_hash)", None),  # special-cased: needs prev_bundle
    ("Entry↔payload identity binding (V12b)", check_12_entry_payload_binding),
]


def run_checks(
    bundle: dict,
    prev_bundle: dict | None,
    trusted_platform_keys: dict[str, str] | None = None,
) -> list[CheckResult]:
    results: list[CheckResult] = []

    entry_hash: bytes | None = None
    for number, (name, fn) in enumerate(_CHECKS, start=1):
        try:
            if number == 9:
                status, detail = check_09_entry_hash_and_countersignature(bundle, trusted_platform_keys)
                # Recompute entry_hash again for check 10 — cheap, and keeps
                # check 10 independent of whether check 9 itself passed.
                canonical_fields = {field: bundle["entry"][field] for field in ENTRY_HASH_FIELDS}
                entry_hash = compute_entry_hash(canonical_fields)
            elif number == 10:
                if entry_hash is None:
                    canonical_fields = {field: bundle["entry"][field] for field in ENTRY_HASH_FIELDS}
                    entry_hash = compute_entry_hash(canonical_fields)
                status, detail = check_10_tsa_token(bundle, entry_hash)
            elif number == 11:
                status, detail = check_11_chain_linkage(bundle, prev_bundle)
            else:
                status, detail = fn(bundle)
        except Exception as exc:  # noqa: BLE001 — a malformed/tampered bundle must produce a FAIL, not a crash
            status, detail = "FAIL", f"check raised {type(exc).__name__}: {exc}"

        results.append(CheckResult(number=number, name=name, status=status, detail=detail))

    return results


def _parse_platform_key_args(specs: list[str] | None) -> dict[str, str]:
    """Parses repeated --platform-key KEY_REF=PATH args into {key_ref: pem_text}.
    KEY_REF is the full KMS key-version resource name (== platform_sigs[].kms_key_version).
    Raises VerifierInputError (mapped to EXIT_INPUT_ERROR) on a malformed spec or
    an unreadable/oversized PEM file — never an uncaught traceback."""
    trusted: dict[str, str] = {}
    for spec in specs or []:
        if "=" not in spec:
            raise VerifierInputError(f"--platform-key must be KEY_REF=PATH, got {spec!r}")
        key_ref, path_str = spec.split("=", 1)
        path = Path(path_str)
        try:
            if path.stat().st_size > MAX_PEM_BYTES:
                raise VerifierInputError(f"--platform-key file {path} exceeds {MAX_PEM_BYTES} bytes")
            trusted[key_ref] = path.read_text(encoding="ascii")
        except OSError as exc:
            raise VerifierInputError(f"cannot read --platform-key file {path}: {exc}") from exc
        except UnicodeDecodeError as exc:
            # UnicodeDecodeError is a ValueError, not an OSError — catch it so a
            # binary/non-ASCII PEM yields a named input error (exit 2), not a crash.
            raise VerifierInputError(f"--platform-key file {path} is not valid ASCII PEM: {exc}") from exc
    return trusted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("bundle", type=Path, help="path to a vardryn.attestation.bundle/1.0 JSON file")
    parser.add_argument(
        "--prev-bundle",
        type=Path,
        default=None,
        help="path to the bundle for ledger entry seq-1 (required for check 11 to PASS when seq > 1)",
    )
    parser.add_argument(
        "--platform-key",
        action="append",
        metavar="KEY_REF=PATH",
        default=None,
        help=(
            "pin a trusted platform countersignature public key OUT OF BAND (V09/V09b). "
            "KEY_REF is the full KMS key-version resource name (== platform_sigs[].kms_key_version); "
            "PATH is a PEM file. Repeatable. Without at least one, check 9 SKIPs (platform provenance "
            "cannot be verified from the bundle alone — SCR-001)."
        ),
    )
    args = parser.parse_args()

    # Load all inputs defensively: a malformed, oversized, or unreadable bundle
    # must yield a named [INPUT ERROR] line and EXIT_INPUT_ERROR — never a raw
    # traceback (20d "never crash, never generic error"; 20e T22/T23/T24).
    try:
        bundle = _read_json_file(args.bundle, max_bytes=MAX_BUNDLE_BYTES, label="bundle")
        prev_bundle = (
            _read_json_file(args.prev_bundle, max_bytes=MAX_BUNDLE_BYTES, label="--prev-bundle")
            if args.prev_bundle
            else None
        )
        trusted_platform_keys = _parse_platform_key_args(args.platform_key)
    except VerifierInputError as exc:
        print(f"[INPUT ERROR] {exc}")
        print("\n0 passed, 0 skipped, 0 failed (input could not be loaded)")
        return EXIT_INPUT_ERROR

    results = run_checks(bundle, prev_bundle, trusted_platform_keys)

    for r in results:
        print(f"[{r.status}] {r.number:2d}. {r.name} — {r.detail}")

    passed = sum(1 for r in results if r.status == "PASS")
    skipped = sum(1 for r in results if r.status == "SKIP")
    failed = sum(1 for r in results if r.status == "FAIL")

    print()
    print(f"{passed} passed, {skipped} skipped, {failed} failed (of {len(results)})")

    return EXIT_CHECK_FAILED if failed else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
