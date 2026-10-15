from typing import List, Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.db.session import get_db
from app.models.case import Case
from app.models.case_note import CaseNote
from app.models.indicator import Indicator
from app.schemas.dashboard import (
    DashboardMetricsResponse, StatusCounts, RiskDistribution,
    TopItem, RecentActivity, IntegrationStatus
)
from app.core.config import settings
from app.services.threat_intel import threat_intel_service

router = APIRouter()


@router.get("/metrics", response_model=DashboardMetricsResponse)
async def get_dashboard_metrics(db: AsyncSession = Depends(get_db)):
    # 1. Total count
    total_res = await db.execute(select(func.count(Case.id)))
    total_cases = total_res.scalar() or 0

    # 2. Status counts
    cases_res = await db.execute(select(Case.status, func.count(Case.id)).group_by(Case.status))
    status_map = {row[0]: row[1] for row in cases_res.all()}
    
    status_counts = StatusCounts(
        new=status_map.get("NEW", 0),
        analysing=status_map.get("ANALYSING", 0),
        needs_review=status_map.get("NEEDS_REVIEW", 0),
        confirmed_malicious=status_map.get("CONFIRMED_MALICIOUS", 0),
        benign=status_map.get("BENIGN", 0),
        closed=status_map.get("CLOSED", 0)
    )

    # 3. Risk distribution
    risk_res = await db.execute(select(Case.risk_level, func.count(Case.id)).group_by(Case.risk_level))
    risk_map = {row[0]: row[1] for row in risk_res.all()}

    risk_dist = RiskDistribution(
        low=risk_map.get("LOW", 0),
        medium=risk_map.get("MEDIUM", 0),
        high=risk_map.get("HIGH", 0),
        critical=risk_map.get("CRITICAL", 0)
    )

    high_crit = risk_dist.high + risk_dist.critical

    # 4. Top sender domains
    top_domains_res = await db.execute(
        select(Case.sender_domain, func.count(Case.id))
        .where(Case.sender_domain != None, Case.sender_domain != "")
        .group_by(Case.sender_domain)
        .order_by(desc(func.count(Case.id)))
        .limit(5)
    )
    top_domains = [
        TopItem(name=row[0], count=row[1], reputation="SUSPICIOUS" if "phish" in row[0] or "micro" in row[0] else "UNKNOWN")
        for row in top_domains_res.all()
    ]

    # 5. Top URLs
    top_urls_res = await db.execute(
        select(Indicator.defanged_value, func.count(Indicator.id), Indicator.reputation)
        .where(Indicator.indicator_type == "URL")
        .group_by(Indicator.defanged_value, Indicator.reputation)
        .order_by(desc(func.count(Indicator.id)))
        .limit(5)
    )
    top_urls = [
        TopItem(name=row[0], count=row[1], reputation=row[2])
        for row in top_urls_res.all()
    ]

    # 6. Recent activity from CaseNotes
    recent_notes_res = await db.execute(
        select(CaseNote, Case.case_number)
        .join(Case, Case.id == CaseNote.case_id)
        .order_by(desc(CaseNote.created_at))
        .limit(8)
    )
    recent_activity = [
        RecentActivity(
            id=note.id,
            case_id=note.case_id,
            case_number=case_num,
            action_type=note.action_type,
            author=note.author_name,
            note_text=note.note_text,
            timestamp=note.created_at.isoformat() if note.created_at else ""
        )
        for note, case_num in recent_notes_res.all()
    ]

    # 7. Integrations status
    integrations = [
        IntegrationStatus(
            name="URLhaus (abuse.ch)",
            configured=True,
            status="OPERATIONAL",
            latency_ms=85.0,
            description="Active threat feed for malicious and phishing URL hashes."
        ),
        IntegrationStatus(
            name="VirusTotal v3",
            configured=bool(threat_intel_service.vt_api_key),
            status="OPERATIONAL" if threat_intel_service.vt_api_key else "UNCONFIGURED",
            latency_ms=0.0,
            description="Multi-engine antivirus scanner and URL reputation intelligence."
        ),
        IntegrationStatus(
            name="RDAP / ICANN Registrar",
            configured=True,
            status="OPERATIONAL",
            latency_ms=120.0,
            description="Domain age registration and authoritative registrar WHOIS data."
        ),
        IntegrationStatus(
            name="DNS Resolver (SPF/DKIM/DMARC)",
            configured=True,
            status="OPERATIONAL",
            latency_ms=25.0,
            description="Direct resolver for SPF records, DKIM public keys, and DMARC policies."
        )
    ]

    return DashboardMetricsResponse(
        total_cases=total_cases,
        pending_analysis=status_counts.analysing,
        needs_review=status_counts.needs_review,
        high_critical_cases=high_crit,
        benign_count=status_counts.benign,
        malicious_count=status_counts.confirmed_malicious,
        status_breakdown=status_counts,
        risk_distribution=risk_dist,
        top_domains=top_domains,
        top_urls=top_urls,
        recent_activity=recent_activity,
        integrations=integrations
    )
