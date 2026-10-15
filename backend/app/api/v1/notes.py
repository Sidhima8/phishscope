from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.db.session import get_db
from app.models.case import Case
from app.models.case_note import CaseNote
from app.models.user import User
from app.schemas.case_note import CaseNoteCreate, CaseNoteResponse
from app.api.v1.auth import get_current_user

router = APIRouter()


@router.get("/{case_id}", response_model=List[CaseNoteResponse])
async def get_case_notes(case_id: int, db: AsyncSession = Depends(get_db)):
    case = await db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    query = select(CaseNote).where(CaseNote.case_id == case_id).order_by(desc(CaseNote.created_at))
    res = await db.execute(query)
    return res.scalars().all()


@router.post("/{case_id}", response_model=CaseNoteResponse)
async def add_case_note(
    case_id: int,
    payload: CaseNoteCreate,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    case = await db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    if not payload.note_text.strip():
        raise HTTPException(status_code=400, detail="Note text cannot be empty")

    author_name = current_user.full_name if current_user else "Analyst"
    note = CaseNote(
        case_id=case.id,
        user_id=current_user.id if current_user else None,
        author_name=author_name,
        note_text=payload.note_text.strip(),
        action_type=payload.action_type or "NOTE"
    )
    db.add(note)
    await db.commit()
    await db.refresh(note)
    return note
