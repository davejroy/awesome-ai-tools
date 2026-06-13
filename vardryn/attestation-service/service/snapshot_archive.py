"""
WORM snapshot archival — §3 `snapshot_uri`.

`attestation_ledger.snapshot_uri` points at the exact bytes served as the
trusted confirmation view (service/snapshot.py) for a ledger entry, stored
in a GCS bucket with Bucket Lock / retention configured (see
vardryn/terraform/modules/cloud-storage) so it cannot be altered or deleted
even by the project owner before the retention period expires.

`SnapshotArchiver` is a small Protocol so `webauthn_ceremony.complete_ceremony`
can be tested with an in-memory fake, without GCS credentials.

ENGINEERING-CONFIDENCE NOTE: `GcsSnapshotArchiver` has NOT been exercised
against a live GCS bucket in this repository — no GCP project is
provisioned in this dev environment. The `google.cloud.storage` calls match
the documented client API; confirming this against a real WORM-locked
bucket is a Week 3 exit-criteria item.
"""

from __future__ import annotations

from typing import Protocol


class SnapshotArchiver(Protocol):
    def archive(self, *, tenant_id: str, entry_id: str, snapshot_bytes: bytes) -> str:
        """Stores `snapshot_bytes` and returns its `gs://bucket/object` URI."""
        ...

    def retrieve(self, uri: str) -> bytes:
        """Returns the bytes previously stored at `uri` (as returned by
        `archive`) — needed to re-export a bundle (§4) for a ledger entry
        after the original ceremony's in-memory snapshot_bytes is gone."""
        ...


class GcsSnapshotArchiver:
    """`client` is a `google.cloud.storage.Client` (typed loosely so this
    module imports without `google-cloud-storage` installed)."""

    def __init__(self, client: object, bucket_name: str):
        self.client = client
        self.bucket_name = bucket_name

    def archive(self, *, tenant_id: str, entry_id: str, snapshot_bytes: bytes) -> str:
        object_name = f"{tenant_id}/{entry_id}/snapshot.html"
        bucket = self.client.bucket(self.bucket_name)
        blob = bucket.blob(object_name)
        blob.upload_from_string(snapshot_bytes, content_type="text/html; charset=utf-8")
        return f"gs://{self.bucket_name}/{object_name}"

    def retrieve(self, uri: str) -> bytes:
        prefix = f"gs://{self.bucket_name}/"
        if not uri.startswith(prefix):
            raise ValueError(f"uri {uri!r} is not in bucket {self.bucket_name!r}")
        object_name = uri[len(prefix):]
        bucket = self.client.bucket(self.bucket_name)
        blob = bucket.blob(object_name)
        return blob.download_as_bytes()
