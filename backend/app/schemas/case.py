from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel, ConfigDict
from app.schemas.finding import FindingResponse
from app.schemas.indicator import IndicatorResponse
from app.schemas.attachment import AttachmentResponse
from app.schemas.case_note import CaseNoteResponse


class CaseBase(BaseModel):
    title: str
    subject: Optional[str] = None
    sender: Optional[str] = None
    sender_domain: Optional[str] = None


class CaseCreateManual(BaseModel):
    raw_content: str  # raw headers + body pasted by analyst
    title: Optional[str] = None


class CaseStatusUpdate(BaseModel):
    status: str  # NEW, ANALYSING, NEEDS_REVIEW, CONFIRMED_MALICIOUS, BENIGN, CLOSED
    reason: Optional[str] = None
    confirmed_by_analyst: bool = False


class CaseAssignUpdate(BaseModel):
    assigned_to_id: Optional[int] = None


class CaseListResponse(BaseModel):
    id: int
    case_number: str
    title: str
    subject: Optional[str] = None
    sender: Optional[str] = None
    sender_domain: Optional[str] = None
    file_hash_sha256: str
    original_file_name: Optional[str] = None
    status: str
    risk_score: int
    risk_level: str
    confidence: str
    created_at: datetime
    updated_at: datetime
    findings_count: int = 0
    indicators_count: int = 0
    attachments_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class CaseDetailResponse(BaseModel):
    id: int
    case_number: str
    title: str
    subject: Optional[str] = None
    sender: Optional[str] = None
    sender_domain: Optional[str] = None
    recipients: Optional[List[str]] = None
    file_hash_sha256: str
    original_file_name: Optional[str] = None
    
    raw_headers: Optional[str] = None
    raw_body_text: Optional[str] = None
    raw_body_html: Optional[str] = None
    
    status: str
    risk_score: int
    risk_level: str
    confidence: str
    
    assigned_to_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None
    
    auth_summary: Optional[Dict[str, Any]] = None
    mime_structure: Optional[Dict[str, Any]] = None
    received_hops: Optional[List[Dict[str, Any]]] = None
    threat_intel_summary: Optional[Dict[str, Any]] = None
    mitre_techniques: Optional[List[Dict[str, Any]]] = None
    executive_summary: Optional[str] = None
    
    completed_checks: int = 0
    failed_checks: int = 0
    unavailable_checks: int = 0

    findings: List[FindingResponse] = []
    indicators: List[IndicatorResponse] = []
    attachments: List[AttachmentResponse] = []
    notes: List[CaseNoteResponse] = []

    model_config = ConfigDict(from_attributes=True)


class CaseCompareRequest(BaseModel):
    case_ids: List[int]


class CaseCompareItem(BaseModel):
    case_id: int
    case_number: str
    subject: Optional[str] = None
    sender: Optional[str] = None
    sender_domain: Optional[str] = None
    risk_score: int
    risk_level: str
    indicators: List[str]
    sha256: str


class CaseCompareResponse(BaseModel):
    cases: List[CaseCompareItem]
    common_indicators: List[str]
    common_sender_domains: List[str]
    similarity_score: float
    analysis_notes: str
