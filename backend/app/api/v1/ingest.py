import hashlib
from typing import List, Optional
from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.case import Case
from app.models.case_note import CaseNote
from app.models.user import User
from app.schemas.case import CaseCreateManual
from app.services.analysis_orchestrator import run_full_case_analysis, generate_case_number
from app.api.v1.auth import get_current_user

router = APIRouter()

MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024  # 25MB


@router.post("/upload")
async def upload_eml_files(
    background_tasks: BackgroundTasks,
    files: List[UploadFile] = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """
    Upload one or more .eml files.
    Calculates raw SHA-256 evidence hash, creates case records,
    and enqueues genuine analysis jobs.
    """
    if not files:
        raise HTTPException(status_code=400, detail="No files provided")

    created_cases = []

    for file in files:
        filename = file.filename or "uploaded_message.eml"
        content = await file.read()
        
        if len(content) > MAX_FILE_SIZE_BYTES:
            raise HTTPException(status_code=400, detail=f"File {filename} exceeds 25MB limit")

        sha256_hash = hashlib.sha256(content).hexdigest()
        case_num = generate_case_number()

        # Try decoding as text for initial inspection
        try:
            raw_text = content.decode("utf-8", errors="replace")
        except Exception:
            raw_text = content.decode("latin-1", errors="replace")

        # Split headers from body roughly for database storage
        parts = raw_text.split("\n\n", 1)
        raw_headers = parts[0]
        raw_body = parts[1] if len(parts) > 1 else ""

        case = Case(
            case_number=case_num,
            title=f"Investigation: {filename}",
            subject=filename,
            file_hash_sha256=sha256_hash,
            original_file_name=filename,
            raw_headers=raw_headers,
            raw_body_text=raw_body,
            status="ANALYSING",
            risk_score=0,
            risk_level="LOW",
            confidence="MEDIUM",
            assigned_to_id=current_user.id if current_user else None,
        )
        db.add(case)
        await db.commit()
        await db.refresh(case)

        # Record ingestion note
        init_note = CaseNote(
            case_id=case.id,
            user_id=current_user.id if current_user else None,
            author_name=current_user.full_name if current_user else "SOC Ingest",
            note_text=f"Email file '{filename}' ingested. SHA-256 evidence hash: {sha256_hash}. Background forensic analysis initiated.",
            action_type="ANALYSIS_STARTED"
        )
        db.add(init_note)
        await db.commit()

        # Schedule genuine dynamic analysis in background
        background_tasks.add_task(run_full_case_analysis, case.id)

        created_cases.append({
            "case_id": case.id,
            "case_number": case.case_number,
            "filename": filename,
            "sha256": sha256_hash,
            "status": "ANALYSING"
        })

    return {
        "message": f"Successfully ingested {len(created_cases)} email(s) for analysis",
        "cases": created_cases
    }


@router.post("/raw")
async def ingest_raw_email(
    payload: CaseCreateManual,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """
    Ingest manually pasted raw email headers and body.
    """
    raw_str = payload.raw_content.strip()
    if not raw_str:
        raise HTTPException(status_code=400, detail="Pasted email content cannot be empty")

    content_bytes = raw_str.encode("utf-8")
    sha256_hash = hashlib.sha256(content_bytes).hexdigest()
    case_num = generate_case_number()

    parts = raw_str.split("\n\n", 1)
    raw_headers = parts[0]
    raw_body = parts[1] if len(parts) > 1 else ""

    case = Case(
        case_number=case_num,
        title=payload.title or f"Manual Ingest {case_num}",
        subject="Pasted Raw Message",
        file_hash_sha256=sha256_hash,
        original_file_name="pasted_raw_input.eml",
        raw_headers=raw_headers,
        raw_body_text=raw_body,
        status="ANALYSING",
        risk_score=0,
        risk_level="LOW",
        confidence="MEDIUM",
        assigned_to_id=current_user.id if current_user else None,
    )
    db.add(case)
    await db.commit()
    await db.refresh(case)

    # Initial Note
    note = CaseNote(
        case_id=case.id,
        user_id=current_user.id if current_user else None,
        author_name=current_user.full_name if current_user else "Analyst",
        note_text=f"Raw email payload pasted. SHA-256 evidence: {sha256_hash}. Dynamic analysis started.",
        action_type="ANALYSIS_STARTED"
    )
    db.add(note)
    await db.commit()

    background_tasks.add_task(run_full_case_analysis, case.id)

    return {
        "message": "Raw email successfully ingested",
        "case_id": case.id,
        "case_number": case.case_number,
        "sha256": sha256_hash,
        "status": "ANALYSING"
    }


@router.get("/samples")
async def list_available_samples():
    """List preloaded demonstration and test email scenarios."""
    return [
        {
            "id": "phish_m365",
            "name": "Microsoft 365 Credential Harvest",
            "filename": "phish_m365_credential_harvest.eml",
            "threat_category": "Credential Phishing / Typosquatting",
            "expected_risk": "CRITICAL"
        },
        {
            "id": "bec_fraud",
            "name": "CEO Executive Wire Fraud (BEC)",
            "filename": "bec_ceo_wire_fraud.eml",
            "threat_category": "Business Email Compromise",
            "expected_risk": "HIGH"
        },
        {
            "id": "malicious_attach",
            "name": "Overdue Invoice (Double Extension Payload)",
            "filename": "malicious_double_extension_attachment.eml",
            "threat_category": "Malicious Attachment",
            "expected_risk": "CRITICAL"
        },
        {
            "id": "legit_newsletter",
            "name": "Legitimate Tech Security Digest",
            "filename": "legitimate_newsletter.eml",
            "threat_category": "Clean Operational Email",
            "expected_risk": "LOW"
        },
        {
            "id": "malformed",
            "name": "Corrupted Headers & Edge Case",
            "filename": "malformed_headers.eml",
            "threat_category": "Malformed Edge Case",
            "expected_risk": "LOW"
        }
    ]


@router.post("/sample/{sample_id}")
async def ingest_sample_scenario(
    sample_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Ingest a preloaded test email scenario and trigger dynamic analysis."""
    import os
    sample_map = {
        "phish_m365": "phish_m365_credential_harvest.eml",
        "bec_fraud": "bec_ceo_wire_fraud.eml",
        "malicious_attach": "malicious_double_extension_attachment.eml",
        "legit_newsletter": "legitimate_newsletter.eml",
        "malformed": "malformed_headers.eml"
    }

    if sample_id not in sample_map:
        raise HTTPException(status_code=404, detail="Sample scenario not found")

    filename = sample_map[sample_id]
    current_dir = os.path.dirname(os.path.abspath(__file__))
    samples_dir = os.path.abspath(os.path.join(current_dir, "..", "..", "..", "samples"))
    sample_path = os.path.join(samples_dir, filename)

    if not os.path.exists(sample_path):
        raise HTTPException(status_code=404, detail=f"Sample file {filename} not found at {sample_path}")

    with open(sample_path, "rb") as f:
        content_bytes = f.read()

    sha256_hash = hashlib.sha256(content_bytes).hexdigest()
    case_num = generate_case_number()

    try:
        raw_text = content_bytes.decode("utf-8", errors="replace")
    except Exception:
        raw_text = content_bytes.decode("latin-1", errors="replace")

    parts = raw_text.split("\n\n", 1)
    raw_headers = parts[0]
    raw_body = parts[1] if len(parts) > 1 else ""

    case = Case(
        case_number=case_num,
        title=f"Sample: {filename.replace('.eml', '').replace('_', ' ').title()}",
        subject=f"Sample: {filename}",
        file_hash_sha256=sha256_hash,
        original_file_name=filename,
        raw_headers=raw_headers,
        raw_body_text=raw_body,
        status="ANALYSING",
        risk_score=0,
        risk_level="LOW",
        confidence="MEDIUM",
        assigned_to_id=current_user.id if current_user else None,
    )
    db.add(case)
    await db.commit()
    await db.refresh(case)

    # Initial Note
    note = CaseNote(
        case_id=case.id,
        user_id=current_user.id if current_user else None,
        author_name=current_user.full_name if current_user else "Analyst",
        note_text=f"Demonstration sample '{filename}' ingested. Triggering dynamic forensic pipeline.",
        action_type="ANALYSIS_STARTED"
    )
    db.add(note)
    await db.commit()

    background_tasks.add_task(run_full_case_analysis, case.id)

    return {
        "message": f"Sample scenario '{filename}' queued for analysis",
        "case_id": case.id,
        "case_number": case.case_number,
        "sha256": sha256_hash,
        "status": "ANALYSING"
    }

