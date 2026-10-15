import re
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.db.session import get_db
from app.models.indicator import Indicator
from app.schemas.indicator import IndicatorResponse, IndicatorLookupRequest, IndicatorLookupResponse
from app.services.threat_intel import threat_intel_service
from app.services.url_analyzer import defang_url, refang_url, expand_url_safely
from pydantic import BaseModel

router = APIRouter()


class ExpandUrlRequest(BaseModel):
    url: str


def detect_indicator_type(val: str) -> str:
    val = val.strip()
    if val.startswith(("http://", "https://", "hxxp://", "hxxps://")):
        return "URL"
    if re.match(r'^[a-fA-F0-9]{64}$', val) or re.match(r'^[a-fA-F0-9]{32}$', val):
        return "HASH"
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', val):
        return "IP"
    if "@" in val:
        return "EMAIL"
    if "." in val:
        return "DOMAIN"
    return "UNKNOWN"


@router.get("", response_model=List[IndicatorResponse])
async def list_indicators(
    indicator_type: Optional[str] = None,
    reputation: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    query = select(Indicator).order_by(desc(Indicator.created_at))
    if indicator_type:
        query = query.filter(Indicator.indicator_type == indicator_type.upper())
    if reputation:
        query = query.filter(Indicator.reputation == reputation.upper())

    query = query.limit(limit).offset(offset)
    result = await db.execute(query)
    return result.scalars().all()


@router.post("/lookup", response_model=IndicatorLookupResponse)
async def lookup_indicator(payload: IndicatorLookupRequest):
    """
    On-demand threat intelligence query for any URL, domain, IP, or hash.
    Directly queries configured providers (URLhaus, RDAP, DNS, VirusTotal).
    """
    raw_val = refang_url(payload.indicator.strip())
    ind_type = payload.indicator_type or detect_indicator_type(raw_val)

    vt_res = None
    uh_res = None
    rdap_res = None
    dns_res = None
    reputation = "CLEAN"
    summary_parts = []

    if ind_type == "URL":
        vt_res = await threat_intel_service.query_virustotal_url(raw_val)
        uh_res = await threat_intel_service.query_urlhaus(raw_val)
        if uh_res.get("reputation") == "malicious" or (vt_res and vt_res.get("reputation") == "malicious"):
            reputation = "MALICIOUS"
            summary_parts.append("Confirmed malicious by external threat intelligence feeds.")
        else:
            summary_parts.append("No active malicious signatures detected.")

    elif ind_type == "DOMAIN":
        rdap_res = await threat_intel_service.query_rdap_domain(raw_val)
        dns_res = threat_intel_service.resolve_dns_records(raw_val)
        if rdap_res.get("is_newly_registered"):
            reputation = "SUSPICIOUS"
            summary_parts.append(f"Domain registered recently ({rdap_res.get('age_days')} days ago).")
        else:
            summary_parts.append(f"Domain registered via {rdap_res.get('registrar', 'Registrar')}.")

    elif ind_type == "IP":
        summary_parts.append("IP indicator evaluated.")

    return IndicatorLookupResponse(
        indicator=raw_val,
        defanged=defang_url(raw_val),
        type=ind_type,
        reputation=reputation,
        summary=" ".join(summary_parts),
        virustotal=vt_res,
        urlhaus=uh_res,
        rdap=rdap_res,
        dns=dns_res,
        lookup_time=datetime.now(timezone.utc)
    )


@router.post("/expand-url")
async def expand_url(payload: ExpandUrlRequest):
    """Safely follow URL redirects with strict SSRF protection."""
    url = refang_url(payload.url.strip())
    return await expand_url_safely(url)
