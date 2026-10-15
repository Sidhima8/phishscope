from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict


class AttachmentResponse(BaseModel):
    id: int
    case_id: int
    filename: str
    content_type: Optional[str] = None
    size_bytes: int
    sha256_hash: str
    md5_hash: str
    risk_level: str
    risk_factors: Optional[List[str]] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
