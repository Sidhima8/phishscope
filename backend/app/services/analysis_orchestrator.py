import random
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import AsyncSessionLocal
from app.models.case import Case
from app.models.finding import Finding
from app.models.indicator import Indicator
from app.models.attachment import Attachment
from app.models.case_note import CaseNote
from app.services.email_parser import parse_email_message
from app.services.auth_analyzer import analyze_email_authentication
from app.services.url_analyzer import extract_urls_from_content, inspect_url
from app.services.threat_intel import threat_intel_service
from app.services.content_analyzer import analyze_email_content
from app.services.risk_engine import calculate_risk_score


def generate_case_number() -> str:
    """Generate professional SOC case ID, e.g. PS-20261015-8492"""
    date_part = datetime.now(timezone.utc).strftime("%Y%m%d")
    rand_part = random.randint(1000, 9999)
    return f"PS-{date_part}-{rand_part}"


async def run_full_case_analysis(case_id: int):
    """
    Genuine runtime analysis pipeline executed asynchronously.
    Processes the raw email, analyzes headers, authentication, URLs, content,
    queries threat intelligence, computes risk score, and persists findings.
    """
    async with AsyncSessionLocal() as session:
        # 1. Fetch Case record
        case = await session.get(Case, case_id)
        if not case:
            return

        case.status = "ANALYSING"
        await session.commit()

        try:
            # 2. Parse Raw Email Content
            raw_bytes = case.raw_headers.encode("utf-8") if case.raw_headers else b""
            if case.raw_body_text or case.raw_body_html:
                full_raw = f"{case.raw_headers}\n\n{case.raw_body_text or ''}\n\n{case.raw_body_html or ''}"
                raw_bytes = full_raw.encode("utf-8", errors="replace")

            parsed = parse_email_message(raw_bytes)

            # Update Case primary metadata
            case.subject = parsed.subject or case.subject or "No Subject"
            case.sender = parsed.from_header or case.sender or "Unknown Sender"
            case.sender_domain = parsed.from_domain or ""
            case.recipients = parsed.to_recipients
            case.raw_headers = parsed.raw_headers
            case.raw_body_text = parsed.body_text
            case.raw_body_html = parsed.body_html
            case.mime_structure = parsed.mime_structure
            case.received_hops = parsed.received_hops

            all_findings = []
            checks_attempted = 10
            unavailable_count = 0

            # 3. Header & Authentication Analysis
            auth_result = analyze_email_authentication(parsed)
            case.auth_summary = auth_result.summary_dict
            all_findings.extend(auth_result.findings)

            # 4. Content & Attachment Analysis
            content_result = analyze_email_content(parsed)
            all_findings.extend(content_result.findings)
            case.mitre_techniques = content_result.mitre_techniques

            # Persist Attachments
            for att in parsed.attachments:
                # Determine risk level for attachment
                ext = att["filename"].split(".")[-1].lower() if "." in att["filename"] else ""
                att_risk = "LOW"
                factors = []
                if ext in ("exe", "scr", "bat", "vbs", "ps1", "hta"):
                    att_risk = "CRITICAL"
                    factors.append("Executable Payload")
                elif ext in ("docm", "xlsm", "iso", "img"):
                    att_risk = "HIGH"
                    factors.append("Macro or Container")

                attachment_obj = Attachment(
                    case_id=case.id,
                    filename=att["filename"],
                    content_type=att.get("content_type"),
                    size_bytes=att["size_bytes"],
                    sha256_hash=att["sha256"],
                    md5_hash=att["md5"],
                    risk_level=att_risk,
                    risk_factors=factors
                )
                session.add(attachment_obj)

            # 5. URL & Domain Investigation
            extracted_urls = extract_urls_from_content(parsed.body_text, parsed.body_html)
            url_reputations = {}

            for ext_url in extracted_urls[:15]:  # Process up to 15 URLs
                inspected, url_findings = inspect_url(ext_url)
                all_findings.extend(url_findings)

                # Query Threat Intelligence (URLhaus)
                uh_res = await threat_intel_service.query_urlhaus(inspected.raw_url)
                vt_res = await threat_intel_service.query_virustotal_url(inspected.raw_url)
                
                reputation = "CLEAN"
                if uh_res.get("reputation") == "malicious" or vt_res.get("reputation") == "malicious":
                    reputation = "MALICIOUS"
                    all_findings.append({
                        "indicator_name": "Active Malicious URL (Threat Intel Feed)",
                        "severity": "CRITICAL",
                        "category": "THREAT_INTEL",
                        "observed_evidence": f"URL {inspected.defanged_url} flagged by {uh_res.get('provider') if uh_res.get('reputation') == 'malicious' else 'VirusTotal'}",
                        "explanation": "External threat intelligence reports this destination as an active distribution point for phishing or malware.",
                        "source": "Threat Intelligence Feed",
                        "confidence": "HIGH",
                        "recommended_step": "Block URL across all perimeter gateways and revoke active browser sessions.",
                        "points_added": 35
                    })
                elif inspected.is_lookalike or inspected.anchor_mismatch:
                    reputation = "SUSPICIOUS"

                provider_data = {
                    "urlhaus": uh_res,
                    "virustotal": vt_res
                }

                # Save Indicator
                ind_obj = Indicator(
                    case_id=case.id,
                    indicator_type="URL",
                    raw_value=inspected.raw_url,
                    defanged_value=inspected.defanged_url,
                    reputation=reputation,
                    flags=inspected.flags,
                    provider_results=provider_data
                )
                session.add(ind_obj)

            # If sender domain exists, check RDAP
            if parsed.from_domain:
                rdap_res = await threat_intel_service.query_rdap_domain(parsed.from_domain)
                if rdap_res.get("is_newly_registered"):
                    all_findings.append({
                        "indicator_name": "Newly Registered Sender Domain (<30 days)",
                        "severity": "HIGH",
                        "category": "THREAT_INTEL",
                        "observed_evidence": f"Domain '{parsed.from_domain}' registered {rdap_res.get('age_days')} day(s) ago (Registrar: {rdap_res.get('registrar')})",
                        "explanation": "Newly registered domains lack legitimate reputation history and are overwhelmingly used in ephemeral phishing campaigns.",
                        "source": "RDAP WHOIS Intelligence",
                        "confidence": "HIGH",
                        "recommended_step": "Temporarily quarantine mail from newly created domains.",
                        "points_added": 22
                    })
                case.threat_intel_summary = {
                    "sender_domain_rdap": rdap_res
                }

            # Check if VT was unconfigured
            if not threat_intel_service.vt_api_key:
                unavailable_count += 1

            # 6. Compute Explainable Risk Score
            risk_res = calculate_risk_score(
                all_findings,
                total_checks_attempted=checks_attempted,
                unavailable_count=unavailable_count
            )

            case.risk_score = risk_res.risk_score
            case.risk_level = risk_res.risk_level
            case.confidence = risk_res.confidence
            case.completed_checks = risk_res.completed_checks
            case.failed_checks = risk_res.failed_checks
            case.unavailable_checks = risk_res.unavailable_checks
            case.executive_summary = f"{risk_res.explanation} {content_result.summary_text}"
            case.status = "NEEDS_REVIEW" if risk_res.risk_score >= 25 else "BENIGN"
            case.completed_at = datetime.now(timezone.utc)

            # 7. Persist Scored Findings
            for sf in risk_res.scored_findings:
                finding_obj = Finding(
                    case_id=case.id,
                    indicator_name=sf["indicator_name"],
                    severity=sf["severity"],
                    category=sf["category"],
                    observed_evidence=sf["observed_evidence"],
                    explanation=sf["explanation"],
                    source=sf["source"],
                    confidence=sf.get("confidence", "HIGH"),
                    recommended_step=sf.get("recommended_step"),
                    points_added=sf.get("effective_points", sf.get("points_added", 0))
                )
                session.add(finding_obj)

            # 8. Record Automated Analysis Case Note
            note_obj = CaseNote(
                case_id=case.id,
                author_name="Automated Analysis Engine",
                note_text=f"Dynamic analysis concluded with Risk Score {case.risk_score}/100 ({case.risk_level}). Identified {len(risk_res.scored_findings)} key finding(s). Status moved to {case.status}.",
                action_type="ANALYSIS_COMPLETED"
            )
            session.add(note_obj)

            await session.commit()

        except Exception as e:
            # Handle failure gracefully, recording error note
            case.status = "NEEDS_REVIEW"
            error_note = CaseNote(
                case_id=case.id,
                author_name="Automated Analysis Engine",
                note_text=f"Analysis encountered an anomaly: {str(e)}. Manual analyst review required.",
                action_type="ANALYSIS_STARTED"
            )
            session.add(error_note)
            await session.commit()
