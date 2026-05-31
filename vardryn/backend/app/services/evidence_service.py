"""
Orchestrates the evidence upload pipeline:
  1. Stream file bytes → compute SHA-512 locally
  2. Upload raw file to GCS (WORM bucket)
  3. Sign the digest via Cloud KMS
  4. Persist ledger record to Postgres
  5. Publish event to Pub/Sub for downstream UEBA
"""

import json
import structlog
from datetime import datetime, timezone
from uuid import uuid4

from google.cloud import storage, pubsub_v1

from app.config import settings
from app.services import kms_service

log = structlog.get_logger()

_storage_client: storage.Client | None = None
_pubsub_client: pubsub_v1.PublisherClient | None = None


def _gcs() -> storage.Client:
    global _storage_client
    if _storage_client is None:
        _storage_client = storage.Client(project=settings.gcp_project_id)
    return _storage_client


def _pubsub() -> pubsub_v1.PublisherClient:
    global _pubsub_client
    if _pubsub_client is None:
        _pubsub_client = pubsub_v1.PublisherClient()
    return _pubsub_client


async def upload_evidence(
    file_bytes: bytes,
    filename: str,
    control_id: str,
    uploaded_by: str,
) -> dict:
    evidence_id = str(uuid4())
    gcs_object_name = f"{control_id}/{evidence_id}/{filename}"

    # 1. Hash
    digest = kms_service.sha512_digest(file_bytes)
    sha512_hex = digest.hex()

    # 2. Upload to WORM bucket
    bucket = _gcs().bucket(settings.evidence_bucket)
    blob = bucket.blob(gcs_object_name)
    blob.upload_from_string(file_bytes, content_type="application/octet-stream")
    gcs_uri = f"gs://{settings.evidence_bucket}/{gcs_object_name}"

    log.info("evidence_uploaded_to_gcs", gcs_uri=gcs_uri, sha512=sha512_hex)

    # 3. Sign digest — only the hash crosses the KMS boundary
    signature_b64, key_version = kms_service.sign_digest(digest)

    log.info("evidence_signed", key_version=key_version, control_id=control_id)

    record = {
        "id": evidence_id,
        "control_id": control_id,
        "filename": filename,
        "gcs_uri": gcs_uri,
        "sha512_hash": sha512_hex,
        "kms_signature": signature_b64,
        "kms_key_version": key_version,
        "uploaded_by": uploaded_by,
        "status": "signed",
        "created_at": datetime.now(tz=timezone.utc).isoformat(),
        "signed_at": datetime.now(tz=timezone.utc).isoformat(),
    }

    # 4. TODO: persist record to Postgres via SQLAlchemy async session

    # 5. Publish audit event
    if settings.pubsub_evidence_topic:
        _pubsub().publish(
            settings.pubsub_evidence_topic,
            json.dumps({
                "event": "evidence.uploaded",
                "evidence_id": evidence_id,
                "control_id": control_id,
                "uploaded_by": uploaded_by,
                "sha512": sha512_hex,
            }).encode(),
        )

    return record
