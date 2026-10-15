from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.db.base import Base


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    case_number = Column(String(50), unique=True, index=True, nullable=False)
    title = Column(String(255), nullable=False)
    subject = Column(String(500), nullable=True)
    sender = Column(String(255), nullable=True)
    sender_domain = Column(String(255), nullable=True, index=True)
    recipients = Column(JSON, nullable=True)  # List of emails
    file_hash_sha256 = Column(String(64), index=True, nullable=False)
    original_file_name = Column(String(255), nullable=True)
    
    # Raw email payloads
    raw_headers = Column(Text, nullable=True)
    raw_body_text = Column(Text, nullable=True)
    raw_body_html = Column(Text, nullable=True)
    
    # Status & scoring
    status = Column(String(50), default="NEW", index=True, nullable=False)
    # NEW, ANALYSING, NEEDS_REVIEW, CONFIRMED_MALICIOUS, BENIGN, CLOSED
    risk_score = Column(Integer, default=0, nullable=False)  # 0 to 100
    risk_level = Column(String(50), default="LOW", nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(String(50), default="MEDIUM", nullable=False)  # HIGH, MEDIUM, LOW
    
    # Ownership & Timestamps
    assigned_to_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Forensic analysis artefacts (Stored JSON)
    auth_summary = Column(JSON, nullable=True)          # SPF, DKIM, DMARC, alignment
    mime_structure = Column(JSON, nullable=True)        # Multipart tree
    received_hops = Column(JSON, nullable=True)         # Hop chain with reverse IPs and delays
    threat_intel_summary = Column(JSON, nullable=True)  # VT, URLhaus, RDAP overview
    mitre_techniques = Column(JSON, nullable=True)      # Identified MITRE ATT&CK techniques
    executive_summary = Column(Text, nullable=True)

    # Completed/Failed/Unavailable check counters
    completed_checks = Column(Integer, default=0, nullable=False)
    failed_checks = Column(Integer, default=0, nullable=False)
    unavailable_checks = Column(Integer, default=0, nullable=False)

    # Relationships
    assigned_to = relationship("User", foreign_keys=[assigned_to_id])
    findings = relationship("Finding", back_populates="case", cascade="all, delete-orphan", order_by="desc(Finding.points_added)")
    indicators = relationship("Indicator", back_populates="case", cascade="all, delete-orphan")
    attachments = relationship("Attachment", back_populates="case", cascade="all, delete-orphan")
    notes = relationship("CaseNote", back_populates="case", cascade="all, delete-orphan", order_by="desc(CaseNote.created_at)")
