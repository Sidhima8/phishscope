from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.models.case import Case
from app.services.report_generator import generate_case_pdf_report

router = APIRouter()


@router.get("/{case_id}/pdf")
async def download_case_pdf(case_id: int, db: AsyncSession = Depends(get_db)):
    """Generate and return forensic PDF report for the selected case."""
    query = select(Case).where(Case.id == case_id).options(
        selectinload(Case.findings),
        selectinload(Case.indicators),
        selectinload(Case.attachments),
        selectinload(Case.notes)
    )
    result = await db.execute(query)
    case = result.scalars().first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    case_dict = {
        "case_number": case.case_number,
        "title": case.title,
        "subject": case.subject,
        "sender": case.sender,
        "sender_domain": case.sender_domain,
        "file_hash_sha256": case.file_hash_sha256,
        "status": case.status,
        "risk_score": case.risk_score,
        "risk_level": case.risk_level,
        "confidence": case.confidence,
        "completed_checks": case.completed_checks,
        "unavailable_checks": case.unavailable_checks,
        "executive_summary": case.executive_summary,
        "auth_summary": case.auth_summary or {},
        "findings": [
            {
                "indicator_name": f.indicator_name,
                "severity": f.severity,
                "category": f.category,
                "points_added": f.points_added,
                "observed_evidence": f.observed_evidence,
                "explanation": f.explanation,
                "source": f.source
            }
            for f in case.findings
        ],
        "indicators": [
            {
                "indicator_type": i.indicator_type,
                "defanged_value": i.defanged_value,
                "reputation": i.reputation,
                "flags": i.flags
            }
            for i in case.indicators
        ],
        "notes": [
            {
                "author_name": n.author_name,
                "note_text": n.note_text,
                "action_type": n.action_type,
                "created_at": n.created_at.isoformat() if n.created_at else ""
            }
            for n in case.notes
        ]
    }

    try:
        pdf_bytes = generate_case_pdf_report(case_dict)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to render forensic PDF: {str(e)}")

    filename = f"{case.case_number}_Forensic_Report.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=\"{filename}\""
        }
    )


@router.get("/{case_id}/json")
async def download_case_json(case_id: int, db: AsyncSession = Depends(get_db)):
    """Export the complete forensic evidence package in JSON format."""
    query = select(Case).where(Case.id == case_id).options(
        selectinload(Case.findings),
        selectinload(Case.indicators),
        selectinload(Case.attachments),
        selectinload(Case.notes)
    )
    result = await db.execute(query)
    case = result.scalars().first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    export_pkg = {
        "export_metadata": {
            "platform": "PhishScope Dynamic Forensics",
            "version": "1.0.0",
            "export_type": "Case Evidence Package",
            "case_id": case.id,
            "case_number": case.case_number,
            "evidence_sha256": case.file_hash_sha256
        },
        "case_overview": {
            "subject": case.subject,
            "sender": case.sender,
            "sender_domain": case.sender_domain,
            "recipients": case.recipients,
            "status": case.status,
            "risk_score": case.risk_score,
            "risk_level": case.risk_level,
            "confidence": case.confidence,
            "executive_summary": case.executive_summary,
            "created_at": case.created_at.isoformat() if case.created_at else None,
            "completed_at": case.completed_at.isoformat() if case.completed_at else None
        },
        "authentication": case.auth_summary,
        "mime_structure": case.mime_structure,
        "received_hops": case.received_hops,
        "mitre_attack_techniques": case.mitre_techniques,
        "findings": [
            {
                "id": f.id,
                "indicator_name": f.indicator_name,
                "severity": f.severity,
                "category": f.category,
                "points_added": f.points_added,
                "observed_evidence": f.observed_evidence,
                "explanation": f.explanation,
                "source": f.source,
                "confidence": f.confidence,
                "recommended_step": f.recommended_step
            }
            for f in case.findings
        ],
        "indicators": [
            {
                "id": i.id,
                "type": i.indicator_type,
                "raw_value": i.raw_value,
                "defanged_value": i.defanged_value,
                "reputation": i.reputation,
                "flags": i.flags,
                "provider_results": i.provider_results
            }
            for i in case.indicators
        ],
        "attachments": [
            {
                "id": a.id,
                "filename": a.filename,
                "content_type": a.content_type,
                "size_bytes": a.size_bytes,
                "sha256": a.sha256_hash,
                "md5": a.md5_hash,
                "risk_level": a.risk_level,
                "risk_factors": a.risk_factors
            }
            for a in case.attachments
        ],
        "forensic_timeline": [
            {
                "id": n.id,
                "author": n.author_name,
                "action": n.action_type,
                "text": n.note_text,
                "timestamp": n.created_at.isoformat() if n.created_at else None
            }
            for n in case.notes
        ]
    }

    filename = f"{case.case_number}_Forensic_Export.json"
    return JSONResponse(
        content=export_pkg,
        headers={"Content-Disposition": f"attachment; filename=\"{filename}\""}
    )
