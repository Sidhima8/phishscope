from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, desc
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.models.case import Case
from app.models.case_note import CaseNote
from app.models.finding import Finding
from app.models.indicator import Indicator
from app.models.attachment import Attachment
from app.models.user import User
from app.schemas.case import (
    CaseListResponse, CaseDetailResponse, CaseStatusUpdate,
    CaseAssignUpdate, CaseCompareRequest, CaseCompareResponse, CaseCompareItem
)
from app.api.v1.auth import get_current_user

router = APIRouter()


@router.get("", response_model=List[CaseListResponse])
async def list_cases(
    search: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    risk_level: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    query = select(Case).options(
        selectinload(Case.findings),
        selectinload(Case.indicators),
        selectinload(Case.attachments)
    )

    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            or_(
                Case.case_number.ilike(search_pattern),
                Case.title.ilike(search_pattern),
                Case.subject.ilike(search_pattern),
                Case.sender.ilike(search_pattern),
                Case.sender_domain.ilike(search_pattern),
                Case.file_hash_sha256.ilike(search_pattern)
            )
        )

    if status_filter and status_filter.upper() != "ALL":
        query = query.filter(Case.status == status_filter.upper())

    if risk_level and risk_level.upper() != "ALL":
        query = query.filter(Case.risk_level == risk_level.upper())

    query = query.order_by(desc(Case.created_at)).limit(limit).offset(offset)
    result = await db.execute(query)
    cases = result.scalars().all()

    response = []
    for c in cases:
        item = CaseListResponse(
            id=c.id,
            case_number=c.case_number,
            title=c.title,
            subject=c.subject,
            sender=c.sender,
            sender_domain=c.sender_domain,
            file_hash_sha256=c.file_hash_sha256,
            original_file_name=c.original_file_name,
            status=c.status,
            risk_score=c.risk_score,
            risk_level=c.risk_level,
            confidence=c.confidence,
            created_at=c.created_at,
            updated_at=c.updated_at,
            findings_count=len(c.findings),
            indicators_count=len(c.indicators),
            attachments_count=len(c.attachments)
        )
        response.append(item)

    return response


@router.get("/{case_id}", response_model=CaseDetailResponse)
async def get_case_detail(case_id: int, db: AsyncSession = Depends(get_db)):
    query = select(Case).where(Case.id == case_id).options(
        selectinload(Case.findings),
        selectinload(Case.indicators),
        selectinload(Case.attachments),
        selectinload(Case.notes)
    )
    result = await db.execute(query)
    case = result.scalars().first()
    if not case:
        raise HTTPException(status_code=404, detail="Investigation case not found")
    return case


@router.patch("/{case_id}/status")
async def update_case_status(
    case_id: int,
    payload: CaseStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    case = await db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    new_status = payload.status.upper()
    valid_statuses = {"NEW", "ANALYSING", "NEEDS_REVIEW", "CONFIRMED_MALICIOUS", "BENIGN", "CLOSED"}
    if new_status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status '{new_status}'")

    # Guard: Require explicit analyst confirmation before labelling as confirmed malicious or benign
    if new_status in ("CONFIRMED_MALICIOUS", "BENIGN") and not payload.confirmed_by_analyst:
        raise HTTPException(
            status_code=400,
            detail=f"Marking a case as {new_status} requires explicit analyst confirmation."
        )

    old_status = case.status
    case.status = new_status
    case.updated_at = datetime.now(timezone.utc)

    # Log action note
    note_text = f"Status changed from {old_status} to {new_status}."
    if payload.reason:
        note_text += f" Reason: {payload.reason}"

    note = CaseNote(
        case_id=case.id,
        user_id=current_user.id if current_user else None,
        author_name=current_user.full_name if current_user else "Analyst",
        note_text=note_text,
        action_type="STATUS_CHANGE"
    )
    db.add(note)
    await db.commit()
    return {"message": "Case status updated successfully", "new_status": new_status}


@router.patch("/{case_id}/assign")
async def assign_case(
    case_id: int,
    payload: CaseAssignUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    case = await db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    assignee_name = "Unassigned"
    if payload.assigned_to_id:
        target_user = await db.get(User, payload.assigned_to_id)
        if not target_user:
            raise HTTPException(status_code=404, detail="Target user not found")
        assignee_name = target_user.full_name

    case.assigned_to_id = payload.assigned_to_id
    case.updated_at = datetime.now(timezone.utc)

    note = CaseNote(
        case_id=case.id,
        user_id=current_user.id if current_user else None,
        author_name=current_user.full_name if current_user else "Supervisor",
        note_text=f"Case assigned to {assignee_name}.",
        action_type="ASSIGNMENT"
    )
    db.add(note)
    await db.commit()
    return {"message": f"Case assigned to {assignee_name}"}


@router.post("/compare", response_model=CaseCompareResponse)
async def compare_cases(payload: CaseCompareRequest, db: AsyncSession = Depends(get_db)):
    if len(payload.case_ids) < 2:
        raise HTTPException(status_code=400, detail="Select at least two cases to compare")

    query = select(Case).where(Case.id.in_(payload.case_ids)).options(
        selectinload(Case.indicators)
    )
    result = await db.execute(query)
    cases = result.scalars().all()

    if len(cases) < 2:
        raise HTTPException(status_code=404, detail="Could not find sufficient cases for comparison")

    compare_items = []
    indicators_by_case = []
    sender_domains = set()

    for c in cases:
        ind_vals = [i.defanged_value for i in c.indicators]
        indicators_by_case.append(set(ind_vals))
        if c.sender_domain:
            sender_domains.add(c.sender_domain)

        compare_items.append(CaseCompareItem(
            case_id=c.id,
            case_number=c.case_number,
            subject=c.subject,
            sender=c.sender,
            sender_domain=c.sender_domain,
            risk_score=c.risk_score,
            risk_level=c.risk_level,
            indicators=ind_vals,
            sha256=c.file_hash_sha256
        ))

    # Calculate intersection of indicators
    common_indicators = list(set.intersection(*indicators_by_case)) if indicators_by_case else []
    
    # Calculate union for Jaccard similarity
    union_indicators = list(set.union(*indicators_by_case)) if indicators_by_case else []
    similarity = round(len(common_indicators) / len(union_indicators), 2) if union_indicators else 0.0

    notes = []
    if common_indicators:
        notes.append(f"Identified {len(common_indicators)} shared observable indicator(s) across selected cases.")
    if len(sender_domains) == 1 and cases[0].sender_domain:
        notes.append(f"All compared cases share the same origin domain: '{cases[0].sender_domain}'.")
    if not notes:
        notes.append("No identical indicators shared between the selected cases; different attack infrastructure observed.")

    return CaseCompareResponse(
        cases=compare_items,
        common_indicators=common_indicators,
        common_sender_domains=list(sender_domains),
        similarity_score=similarity,
        analysis_notes=" ".join(notes)
    )


@router.delete("/{case_id}")
async def delete_case(case_id: int, db: AsyncSession = Depends(get_db)):
    case = await db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    await db.delete(case)
    await db.commit()
    return {"message": "Case deleted successfully"}
