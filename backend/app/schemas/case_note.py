from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class CaseNoteCreate(BaseModel):
    note_text: str
    action_type: str = "NOTE"


class CaseNoteResponse(BaseModel):
    id: int
    case_id: int
    user_id: Optional[int] = None
    author_name: str
    note_text: str
    action_type: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
