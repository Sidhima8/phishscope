from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.db.base import Base


class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    
    indicator_type = Column(String(50), nullable=False, index=True)  # URL, DOMAIN, IP, HASH, EMAIL
    raw_value = Column(Text, nullable=False)
    defanged_value = Column(Text, nullable=False)
    reputation = Column(String(50), default="UNKNOWN", index=True, nullable=False)  # CLEAN, SUSPICIOUS, MALICIOUS, UNKNOWN
    
    # Heuristic flags (is_shortener, is_ip_host, is_lookalike, anchor_mismatch, suspicious_tld)
    flags = Column(JSON, nullable=True)
    redirect_chain = Column(JSON, nullable=True)
    provider_results = Column(JSON, nullable=True)  # VirusTotal, URLhaus, RDAP data

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    case = relationship("Case", back_populates="indicators")
