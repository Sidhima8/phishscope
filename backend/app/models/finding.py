from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.db.base import Base


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    
    indicator_name = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category = Column(String(50), nullable=False)  # HEADER, AUTH, URL, CONTENT, ATTACHMENT, THREAT_INTEL
    
    observed_evidence = Column(Text, nullable=False)
    explanation = Column(Text, nullable=False)
    source = Column(String(100), nullable=False)  # e.g. "DNS SPF Resolver", "Heuristic Content Engine"
    confidence = Column(String(50), default="HIGH", nullable=False)  # HIGH, MEDIUM, LOW
    recommended_step = Column(Text, nullable=True)
    points_added = Column(Integer, default=0, nullable=False)
    
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    case = relationship("Case", back_populates="findings")
