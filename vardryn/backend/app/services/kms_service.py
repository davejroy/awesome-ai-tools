"""
Wraps Cloud KMS asymmetric signing for the evidence non-repudiation ledger.

Flow:
  1. Caller computes SHA-512 digest of the evidence file locally.
  2. kms_service.sign_digest() sends *only the digest* to KMS — the file never
     leaves the application boundary.
  3. The returned (signature, key_version) pair is persisted alongside the
     evidence record in Postgres. Auditors can verify offline using the public
     key fetched via get_public_key().
"""

import hashlib
import base64
from typing import Tuple

from google.cloud import kms_v1
from google.cloud.kms_v1 import CryptoKeyVersion

from app.config import settings


_client: kms_v1.KeyManagementServiceClient | None = None


def _get_client() -> kms_v1.KeyManagementServiceClient:
    global _client
    if _client is None:
        _client = kms_v1.KeyManagementServiceClient()
    return _client


def sha512_digest(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def sign_digest(digest: bytes) -> Tuple[str, str]:
    """
    Signs a SHA-512 digest using the evidence signing key.

    Returns:
        (base64_signature, key_version_resource_name)
    """
    client = _get_client()
    key_name = settings.kms_signing_key_id

    # KMS requires the digest wrapped in the appropriate proto message
    digest_proto = kms_v1.Digest(sha512=digest)

    response = client.asymmetric_sign(
        request={
            "name": f"{key_name}/cryptoKeyVersions/1",
            "digest": digest_proto,
        }
    )

    signature_b64 = base64.b64encode(response.signature).decode()
    return signature_b64, response.name


def verify_signature(digest: bytes, signature_b64: str, key_version: str) -> bool:
    """
    Verifies a previously recorded signature. Used by auditors and automated
    integrity checks; never called on the critical upload path.
    """
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes, serialization

    client = _get_client()
    pub_key_response = client.get_public_key(request={"name": key_version})
    public_key = serialization.load_pem_public_key(
        pub_key_response.pem.encode()
    )

    signature = base64.b64decode(signature_b64)
    try:
        public_key.verify(
            signature,
            digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA384()))
        )
        return True
    except Exception:
        return False
