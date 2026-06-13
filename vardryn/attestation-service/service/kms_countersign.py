"""
Cloud KMS countersignature — §3 `platform_sigs`.

Computes a platform countersignature over `entry_hash` using a Cloud KMS
asymmetric signing key (`RSA_SIGN_PSS_4096_SHA512`), and packages the
result into the `platform_sigs` array-entry shape consumed by
`attestation_ledger.platform_sigs` and verified by
`service/platform_signature.py`.

ENGINEERING-CONFIDENCE NOTE: requires a live Cloud KMS key version with IAM
permission `cloudkms.cryptoKeyVersions.useToSign`, and the
`google-cloud-kms` package (deliberately NOT a dependency of the offline
verifier — see platform_signature.py, which does the actual cryptographic
verification with zero Google dependencies). This module has NOT been
exercised against a real KMS key in this repository: no GCP project is
provisioned in this dev environment. The request/response shapes
(`asymmetric_sign`, `get_public_key`, `verified_digest_crc32c`) match the
documented `google.cloud.kms_v1` API as of this writing. Confirming this
against a real `RSA_SIGN_PSS_4096_SHA512` key is a Week 3 exit-criteria
item.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from .platform_signature import (
    SUITE_RSA_PSS_4096_SHA512,
    PlatformSignatureError,
    verify_platform_sig_entry,
)


class KmsCountersignError(Exception):
    pass


@dataclass(frozen=True)
class KmsCountersigner:
    """
    `client` is a `google.cloud.kms_v1.KeyManagementServiceClient` (typed
    loosely here so this module imports without `google-cloud-kms`
    installed; the live service wires in a real client).

    `key_version_name` is a full Cloud KMS resource name:
      projects/{p}/locations/{l}/keyRings/{r}/cryptoKeys/{k}/cryptoKeyVersions/{v}
    The corresponding key MUST be configured with purpose
    `ASYMMETRIC_SIGN` and algorithm `RSA_SIGN_PSS_4096_SHA512`.
    """

    client: object
    key_version_name: str
    suite: str = SUITE_RSA_PSS_4096_SHA512

    def public_key_pem(self) -> str:
        response = self.client.get_public_key(request={"name": self.key_version_name})
        return response.pem

    def countersign(self, entry_hash: bytes) -> dict:
        """
        Returns one `platform_sigs` array entry:
          {"suite", "kms_key_version", "public_key_pem", "sig"}

        `entry_hash` must be the 64-byte SHA-512 digest from
        `entry_hash.compute_entry_hash()`. Cloud KMS signs this digest
        directly (the `digest` field of AsymmetricSignRequest, not raw
        data) — the digest algorithm here MUST match the key's configured
        algorithm (SHA-512 for RSA_SIGN_PSS_4096_SHA512).

        Before returning, self-checks the result with
        `platform_signature.verify_platform_sig_entry()` — a KMS signature
        that doesn't verify against KMS's own reported public key indicates
        a serious problem (e.g. wrong key version, transit corruption) and
        must fail loudly here, before the result is written to the
        append-only ledger.
        """
        if self.suite != SUITE_RSA_PSS_4096_SHA512:
            raise KmsCountersignError(f"unsupported suite {self.suite!r}")

        if len(entry_hash) != 64:
            raise KmsCountersignError(
                f"entry_hash must be a 64-byte SHA-512 digest, got {len(entry_hash)} bytes"
            )

        response = self.client.asymmetric_sign(
            request={
                "name": self.key_version_name,
                "digest": {"sha512": entry_hash},
            }
        )

        # Cloud KMS's data-integrity guidelines recommend checking the
        # returned CRC32C checksums to detect in-transit corruption.
        # https://cloud.google.com/kms/docs/data-integrity-guidelines
        if not response.verified_digest_crc32c:
            raise KmsCountersignError(
                "Cloud KMS response did not report verified_digest_crc32c — "
                "possible request corruption in transit"
            )

        platform_sig = {
            "suite": self.suite,
            "kms_key_version": self.key_version_name,
            "public_key_pem": self.public_key_pem(),
            "sig": base64.b64encode(response.signature).decode("ascii"),
        }

        try:
            verify_platform_sig_entry(platform_sig, entry_hash)
        except PlatformSignatureError as exc:
            raise KmsCountersignError(
                f"KMS-produced signature failed self-verification: {exc}"
            ) from exc

        return platform_sig
