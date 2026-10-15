from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.db.base import Base


class CaseNote(Base):
    __tablename__ = "case_notes"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    author_name = Column(String(255), default="Analyst", nullable=False)
    note_text = Column(Text, nullable=False)
    action_type = Column(String(50), default="NOTE", nullable=False)
    # NOTE, STATUS_CHANGE, ASSIGNMENT, ANALYSIS_STARTED, ANALYSIS_COMPLETED

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    case = relationship("Case", back_populates="notes")
