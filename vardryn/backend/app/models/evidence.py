from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field
from sqlalchemy import Column, DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class EvidenceStatus(str, Enum):
    PENDING = "pending"
    SIGNED = "signed"
    REJECTED = "rejected"


class EvidenceRecord(Base):
    __tablename__ = "evidence_records"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    control_id = Column(String(64), nullable=False, index=True)
    filename = Column(String(512), nullable=False)
    gcs_uri = Column(Text, nullable=False)
    sha512_hash = Column(String(128), nullable=False)
    kms_signature = Column(Text, nullable=False)
    kms_key_version = Column(Text, nullable=False)
    uploaded_by = Column(String(255), nullable=False)
    status = Column(String(32), default=EvidenceStatus.PENDING)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    signed_at = Column(DateTime(timezone=True), nullable=True)


# Pydantic schemas

class EvidenceUploadResponse(BaseModel):
    id: UUID
    control_id: str
    filename: str
    sha512_hash: str
    kms_key_version: str
    status: EvidenceStatus
    created_at: datetime

    class Config:
        from_attributes = True
