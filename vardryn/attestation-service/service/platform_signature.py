"""
Platform countersignature verification — §3 `platform_sigs`.

Verifies a single entry of `attestation_ledger.platform_sigs` against a
recomputed `entry_hash`. This module is VENDORED (copied verbatim) into
verifier/ — it has NO dependency on Cloud KMS or any other Google Cloud
library, only `cryptography` + stdlib, so the offline verifier can confirm
the platform's countersignature without any cloud credentials.

`platform_sigs` is an ARRAY (not a single object) by design (§3): it lets a
second algorithm-agility entry (e.g. a post-quantum signature) be appended
at INSERT time later without a schema migration. `verify_platform_sig_entry`
verifies exactly ONE entry against its own declared `suite`; the verifier
(§5.1) calls it once per entry present and requires at least one to verify.

Suites:
  "RSASSA-PSS-4096-SHA512" — the only suite implemented at this stage
  (Cloud KMS `RSA_SIGN_PSS_4096_SHA512`: PSS with MGF1-SHA512, salt length
  = 64 bytes = SHA-512 digest size, per Cloud KMS's documented parameters).
"""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SUITE_RSA_PSS_4096_SHA512 = "RSASSA-PSS-4096-SHA512"

SUPPORTED_SUITES: frozenset[str] = frozenset({SUITE_RSA_PSS_4096_SHA512})


class PlatformSignatureError(Exception):
    pass


def verify_platform_sig_entry(platform_sig: dict, entry_hash: bytes) -> None:
    """
    Raises PlatformSignatureError if `platform_sig` is not a valid
    signature over `entry_hash` under its declared `suite`.

    Expected shape: {"suite": str, "kms_key_version": str,
    "public_key_pem": str, "sig": str} where `sig` is standard
    (non-urlsafe) base64.
    """
    suite = platform_sig.get("suite")
    if suite not in SUPPORTED_SUITES:
        raise PlatformSignatureError(f"unsupported platform_sigs suite {suite!r}")

    try:
        public_key = serialization.load_pem_public_key(
            platform_sig["public_key_pem"].encode("ascii")
        )
    except Exception as exc:
        raise PlatformSignatureError(f"invalid public_key_pem: {exc}") from exc

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise PlatformSignatureError(
            f"suite {suite!r} requires an RSA public key, got {type(public_key)!r}"
        )

    try:
        sig = base64.b64decode(platform_sig["sig"], validate=True)
    except Exception as exc:
        raise PlatformSignatureError(f"invalid sig encoding: {exc}") from exc

    # Only one suite implemented; the `if` is structured for the next suite
    # to be added as an `elif` without restructuring the dispatch.
    if suite == SUITE_RSA_PSS_4096_SHA512:
        if public_key.key_size != 4096:
            raise PlatformSignatureError(
                f"suite {suite!r} requires a 4096-bit RSA key, got {public_key.key_size}-bit"
            )
        try:
            public_key.verify(
                sig,
                entry_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA512()),
                    salt_length=hashes.SHA512().digest_size,
                ),
                hashes.SHA512(),
            )
        except InvalidSignature as exc:
            raise PlatformSignatureError("platform countersignature does not verify") from exc
