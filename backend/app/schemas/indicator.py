from datetime import datetime
from typing import Optional, Any, Dict, List, Union
from pydantic import BaseModel, ConfigDict


class IndicatorResponse(BaseModel):
    id: int
    case_id: int
    indicator_type: str
    raw_value: str
    defanged_value: str
    reputation: str
    flags: Optional[Union[List[str], Dict[str, Any]]] = None
    redirect_chain: Optional[List[str]] = None
    provider_results: Optional[Dict[str, Any]] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IndicatorLookupRequest(BaseModel):
    indicator: str
    indicator_type: Optional[str] = None  # auto-detected if not specified


class IndicatorLookupResponse(BaseModel):
    indicator: str
    defanged: str
    type: str
    reputation: str
    summary: str
    virustotal: Optional[Dict[str, Any]] = None
    urlhaus: Optional[Dict[str, Any]] = None
    rdap: Optional[Dict[str, Any]] = None
    dns: Optional[Dict[str, Any]] = None
    lookup_time: datetime
