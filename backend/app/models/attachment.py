from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.db.base import Base


class Attachment(Base):
    __tablename__ = "attachments"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    
    filename = Column(String(255), nullable=False)
    content_type = Column(String(100), nullable=True)
    size_bytes = Column(Integer, default=0, nullable=False)
    sha256_hash = Column(String(64), nullable=False, index=True)
    md5_hash = Column(String(32), nullable=False)
    
    risk_level = Column(String(50), default="LOW", nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW
    risk_factors = Column(JSON, nullable=True)  # List of identified risks e.g. ["double_extension", "executable"]

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    case = relationship("Case", back_populates="attachments")
