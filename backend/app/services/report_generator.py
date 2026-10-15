import io
from datetime import datetime, timezone
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch


def generate_case_pdf_report(case_dict: dict) -> bytes:
    """Generate a clean, forensic SOC PDF report using ReportLab."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=6
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=12
    )

    section_header = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=10,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155')
    )

    mono_style = ParagraphStyle(
        'MonoText',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#0f172a')
    )

    # Table Typography Styles
    th_style = ParagraphStyle(
        'TableHead',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.white
    )

    td_style = ParagraphStyle(
        'TableBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=10.5,
        textColor=colors.HexColor('#1e293b'),
        wordWrap='CJK'
    )

    td_bold_style = ParagraphStyle(
        'TableBodyBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=10.5,
        textColor=colors.HexColor('#0f172a'),
        wordWrap='CJK'
    )

    td_mono_style = ParagraphStyle(
        'TableMono',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7,
        leading=9,
        textColor=colors.HexColor('#0f172a'),
        wordWrap='CJK'
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("PHISHSCOPE — FORENSIC INVESTIGATION REPORT", title_style))
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    story.append(Paragraph(f"Generated at: {now_str} | Platform: PhishScope Threat Engine v1.0", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#3b82f6'), spaceAfter=12))

    # 2. Case Overview Table
    risk_level = case_dict.get("risk_level", "LOW")
    risk_score = case_dict.get("risk_score", 0)
    
    risk_color = colors.HexColor('#10b981')  # Low
    if risk_level == "CRITICAL":
        risk_color = colors.HexColor('#ef4444')
    elif risk_level == "HIGH":
        risk_color = colors.HexColor('#f97316')
    elif risk_level == "MEDIUM":
        risk_color = colors.HexColor('#f59e0b')

    overview_data = [
        [
            Paragraph("<b>Case Number:</b>", td_style),
            Paragraph(f"<b>{case_dict.get('case_number', 'N/A')}</b>", td_style),
            Paragraph("<b>Risk Score:</b>", td_style),
            Paragraph(f"<b>{risk_score}/100 ({risk_level})</b>", ParagraphStyle('Score', parent=td_style, fontName='Helvetica-Bold', textColor=risk_color)),
        ],
        [
            Paragraph("<b>Status:</b>", td_style),
            Paragraph(str(case_dict.get('status', 'NEW')), td_style),
            Paragraph("<b>Confidence:</b>", td_style),
            Paragraph(str(case_dict.get('confidence', 'MEDIUM')), td_style),
        ],
        [
            Paragraph("<b>Subject:</b>", td_style),
            Paragraph(str(case_dict.get('subject') or 'No Subject'), td_style),
            Paragraph("<b>Sender:</b>", td_style),
            Paragraph(str(case_dict.get('sender') or 'Unknown'), td_style),
        ],
        [
            Paragraph("<b>Evidence SHA-256:</b>", td_style),
            Paragraph(str(case_dict.get('file_hash_sha256', 'N/A')), td_mono_style),
            Paragraph("<b>Checks Completed:</b>", td_style),
            Paragraph(f"{case_dict.get('completed_checks', 0)} completed / {case_dict.get('unavailable_checks', 0)} unavail", td_style),
        ]
    ]

    t_overview = Table(overview_data, colWidths=[1.3*inch, 2.3*inch, 1.3*inch, 2.3*inch])
    t_overview.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_overview)
    story.append(Spacer(1, 12))

    # 3. Executive Summary
    story.append(Paragraph("Executive Summary & Risk Assessment", section_header))
    summary_text = case_dict.get("executive_summary") or "Comprehensive forensic review completed."
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 10))

    # 4. Authentication Summary (SPF, DKIM, DMARC)
    story.append(Paragraph("Email Authentication & Origin Verification", section_header))
    auth = case_dict.get("auth_summary") or {}
    spf = auth.get("spf", {})
    dkim = auth.get("dkim", {})
    dmarc = auth.get("dmarc", {})

    auth_data = [
        [
            Paragraph("<b>Mechanism</b>", th_style),
            Paragraph("<b>Recorded Status</b>", th_style),
            Paragraph("<b>DNS Record Found</b>", th_style),
            Paragraph("<b>Alignment</b>", th_style),
            Paragraph("<b>Evaluation</b>", th_style),
        ],
        [
            Paragraph("<b>SPF</b>", td_bold_style),
            Paragraph(spf.get("recorded", "none").upper(), td_style),
            Paragraph("Yes" if spf.get("dns_record_found") else "No", td_style),
            Paragraph("Aligned" if spf.get("alignment") else "Unaligned", td_style),
            Paragraph(f"<b>{spf.get('verdict', 'NEUTRAL')}</b>", td_style)
        ],
        [
            Paragraph("<b>DKIM</b>", td_bold_style),
            Paragraph(dkim.get("recorded", "none").upper(), td_style),
            Paragraph("Yes" if dkim.get("dns_key_found") else "No", td_style),
            Paragraph("Aligned" if dkim.get("alignment") else "Unaligned", td_style),
            Paragraph(f"<b>{dkim.get('verdict', 'NEUTRAL')}</b>", td_style)
        ],
        [
            Paragraph("<b>DMARC</b>", td_bold_style),
            Paragraph(dmarc.get("recorded", "none").upper(), td_style),
            Paragraph("Yes" if dmarc.get("dns_record_found") else "No", td_style),
            Paragraph(f"Policy: {dmarc.get('policy', 'none')}", td_style),
            Paragraph(f"<b>{dmarc.get('verdict', 'NEUTRAL')}</b>", td_style)
        ],
    ]
    t_auth = Table(auth_data, colWidths=[1.1*inch, 1.4*inch, 1.5*inch, 1.6*inch, 1.6*inch])
    t_auth.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ffffff')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_auth)
    story.append(Spacer(1, 10))

    # 5. Key Forensic Findings
    story.append(Paragraph("Forensic Findings & Observable Evidence", section_header))
    findings = case_dict.get("findings", [])
    if findings:
        finding_rows = [[
            Paragraph("<b>Indicator Name & Source</b>", th_style),
            Paragraph("<b>Severity</b>", th_style),
            Paragraph("<b>Points</b>", th_style),
            Paragraph("<b>Observed Evidence</b>", th_style)
        ]]
        for f in findings[:10]:  # Top 10 findings in PDF
            name = Paragraph(f"<b>{f.get('indicator_name')}</b><br/><font color='#64748b' size=6.5>{f.get('source')}</font>", td_style)
            sev = Paragraph(f"<b>{f.get('severity', 'INFO')}</b>", td_style)
            pts = Paragraph(f"+{f.get('points_added', 0)}", td_bold_style)
            evidence = Paragraph(f.get('observed_evidence', ''), td_style)
            finding_rows.append([name, sev, pts, evidence])

        t_findings = Table(finding_rows, colWidths=[2.2*inch, 0.9*inch, 0.6*inch, 3.5*inch])
        t_findings.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_findings)
    else:
        story.append(Paragraph("No anomalous indicators observed during automated analysis.", body_style))
    story.append(Spacer(1, 10))

    # 6. Extracted Indicators (URLs and Attachments)
    indicators = case_dict.get("indicators", [])
    if indicators:
        story.append(Paragraph(f"Extracted Indicators ({len(indicators)} Observables)", section_header))
        ind_rows = [[
            Paragraph("<b>Type</b>", th_style),
            Paragraph("<b>Defanged Observable Value</b>", th_style),
            Paragraph("<b>Reputation</b>", th_style),
            Paragraph("<b>Flags</b>", th_style)
        ]]
        for ind in indicators[:8]:
            val_p = Paragraph(ind.get("defanged_value", "")[:75], td_mono_style)
            flags = ", ".join(ind.get("flags", []) or []) if isinstance(ind.get("flags"), list) else ""
            ind_rows.append([
                Paragraph(ind.get("indicator_type", "URL"), td_bold_style),
                val_p,
                Paragraph(ind.get("reputation", "UNKNOWN"), td_style),
                Paragraph(flags or "None", td_style)
            ])
        t_ind = Table(ind_rows, colWidths=[0.9*inch, 3.5*inch, 1.1*inch, 1.7*inch])
        t_ind.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#334155')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(t_ind)
        story.append(Spacer(1, 10))

    # 7. Analyst Notes & Investigation Timeline (FIXED: Zero Overlap via Paragraph flowables)
    notes = case_dict.get("notes", [])
    if notes:
        story.append(Paragraph("Analyst Investigation Timeline & Notes", section_header))
        note_rows = [[
            Paragraph("<b>Timestamp</b>", th_style),
            Paragraph("<b>Author</b>", th_style),
            Paragraph("<b>Type</b>", th_style),
            Paragraph("<b>Note / Action Details</b>", th_style)
        ]]
        for n in notes:
            created_raw = str(n.get("created_at", ""))[:19]
            # Replace T with space and show cleanly
            created_str = created_raw.replace("T", "<br/>")
            author_str = str(n.get("author_name", "Analyst"))
            action_raw = str(n.get("action_type", "NOTE")).replace("_", " ")
            text_str = str(n.get("note_text", ""))

            note_rows.append([
                Paragraph(created_str, td_mono_style),
                Paragraph(author_str, td_bold_style),
                Paragraph(f"<font color='#0284c7'><b>{action_raw}</b></font>", td_style),
                Paragraph(text_str, td_style)
            ])

        t_notes = Table(note_rows, colWidths=[1.2*inch, 1.4*inch, 1.3*inch, 3.3*inch])
        t_notes.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#475569')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_notes)
        story.append(Spacer(1, 10))

    # 8. Disclaimer & Forensic Chain of Custody
    story.append(Spacer(1, 14))
    disclaimer = (
        "<b>Forensic Chain of Custody Notice:</b> This automated forensic report represents the state of the email evidence "
        "and threat intelligence indicators at the time of analysis. Unaltered raw evidence SHA-256 is recorded above. "
        "Threat intelligence reputation results are subject to real-time provider dynamics. Confidential evidence was not submitted to public telemetry."
    )
    story.append(Paragraph(disclaimer, ParagraphStyle('Disc', parent=body_style, fontSize=7, leading=9, textColor=colors.HexColor('#94a3b8'))))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
