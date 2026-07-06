from sqlalchemy import Column, String, Text, JSON
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from uuid import uuid4

from app.models.evidence import Base


class Control(Base):
    __tablename__ = "controls"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    # SCF/OSCAL identifiers
    scf_id = Column(String(64), nullable=False, unique=True, index=True)
    title = Column(String(512), nullable=False)
    description = Column(Text)
    # JSON array of framework tags, e.g. ["CMMC-2.0-L2", "NIST-800-171", "FedRAMP-M"]
    frameworks = Column(JSON, default=list)
    domain = Column(String(128))
    # "met" | "partial" | "not_met" | "not_applicable"
    status = Column(String(32), default="not_met")
