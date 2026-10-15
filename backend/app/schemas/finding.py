from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class FindingResponse(BaseModel):
    id: int
    case_id: int
    indicator_name: str
    severity: str
    category: str
    observed_evidence: str
    explanation: str
    source: str
    confidence: str
    recommended_step: Optional[str] = None
    points_added: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
