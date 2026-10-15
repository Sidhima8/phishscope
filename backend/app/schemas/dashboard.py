from typing import List, Dict, Any
from pydantic import BaseModel


class StatusCounts(BaseModel):
    new: int = 0
    analysing: int = 0
    needs_review: int = 0
    confirmed_malicious: int = 0
    benign: int = 0
    closed: int = 0


class RiskDistribution(BaseModel):
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0


class TopItem(BaseModel):
    name: str
    count: int
    reputation: str = "UNKNOWN"


class RecentActivity(BaseModel):
    id: int
    case_id: int
    case_number: str
    action_type: str
    author: str
    note_text: str
    timestamp: str


class IntegrationStatus(BaseModel):
    name: str
    configured: bool
    status: str  # OPERATIONAL, UNCONFIGURED, ERROR
    latency_ms: float = 0.0
    description: str


class DashboardMetricsResponse(BaseModel):
    total_cases: int
    pending_analysis: int
    needs_review: int
    high_critical_cases: int
    benign_count: int
    malicious_count: int
    status_breakdown: StatusCounts
    risk_distribution: RiskDistribution
    top_domains: List[TopItem]
    top_urls: List[TopItem]
    recent_activity: List[RecentActivity]
    integrations: List[IntegrationStatus]
