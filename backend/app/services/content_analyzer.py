import re
from typing import Dict, Any, List
from app.services.email_parser import ParsedEmail

# Phishing heuristic detection dictionaries
URGENCY_PATTERNS = [
    (r'\b(?:account|access|service)\s+(?:suspended|terminated|disabled|restricted|locked)\b', "Account Suspension / Lockout Threat", 18),
    (r'\b(?:within\s+(?:24|48|12)\s+hours|immediately|immediate\s+action\s+required)\b', "Artificial Urgency Deadline", 16),
    (r'\b(?:unauthorized\s+activity|suspicious\s+login|security\s+alert|compromised)\b', "Security Alert Coercion", 14),
    (r'\b(?:failure\s+to\s+respond|will\s+be\s+permanently\s+deleted)\b', "Punitive Consequence Threat", 16),
]

CREDENTIAL_HARVEST_PATTERNS = [
    (r'\b(?:verify\s+your\s+(?:identity|account|credentials|email))\b', "Credential Verification Request", 22),
    (r'\b(?:confirm\s+your\s+password|login\s+to\s+(?:verify|confirm|restore))\b', "Password / Login Challenge", 24),
    (r'\b(?:update\s+your\s+(?:billing|payment|credit\s+card)\s+(?:details|information))\b', "Payment / Credit Card Harvest", 22),
    (r'\b(?:reactivate\s+your\s+mailbox|mailbox\s+(?:quota|storage)\s+(?:exceeded|full))\b', "Mailbox Quota Extortion", 18),
]

FINANCIAL_BEC_PATTERNS = [
    (r'\b(?:wire\s+transfer|transfer\s+funds|swift\s+transfer|bank\s+transfer)\b', "Wire Transfer Instruction", 22),
    (r'\b(?:updated\s+(?:banking|bank\s+account|payment)\s+details)\b', "Bank Account Detail Alteration", 26),
    (r'\b(?:gift\s+cards?|itunes\s+card|steam\s+card|apple\s+gift)\b', "Gift Card Purchase Request", 28),
    (r'\b(?:invoice\s+(?:attached|due|overdue|payment)|purchase\s+order)\b', "Urgent Invoice / Payment Lure", 14),
    (r'\b(?:payroll\s+update|direct\s+deposit\s+change)\b', "Direct Deposit Fraud", 24),
]

DANGEROUS_EXTENSIONS = {
    "exe": ("Executable binary", "CRITICAL", 35),
    "scr": ("Screensaver executable payload", "CRITICAL", 35),
    "bat": ("Batch script", "CRITICAL", 32),
    "cmd": ("Windows command script", "CRITICAL", 32),
    "vbs": ("VBScript payload", "CRITICAL", 35),
    "js": ("JavaScript standalone script", "HIGH", 28),
    "hta": ("HTML Application payload", "CRITICAL", 35),
    "ps1": ("PowerShell script", "CRITICAL", 32),
    "iso": ("Disk image container", "HIGH", 25),
    "img": ("Disk image container", "HIGH", 25),
    "dll": ("Dynamic link library", "CRITICAL", 32),
    "wsf": ("Windows Script File", "CRITICAL", 32),
    "docm": ("Macro-enabled Word document", "HIGH", 24),
    "xlsm": ("Macro-enabled Excel spreadsheet", "HIGH", 24),
    "pptm": ("Macro-enabled PowerPoint", "HIGH", 24),
    "jar": ("Java archive executable", "HIGH", 24),
}


class ContentAnalysisResult:
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self.mitre_techniques: List[Dict[str, Any]] = []
        self.is_urgent: bool = False
        self.is_credential_harvest: bool = False
        self.is_financial_bec: bool = False
        self.has_dangerous_attachment: bool = False
        self.summary_text: str = ""


def analyze_email_content(email_obj: ParsedEmail) -> ContentAnalysisResult:
    result = ContentAnalysisResult()
    combined_content = f"{email_obj.subject}\n{email_obj.body_text}\n{email_obj.body_html}"

    # 1. Evaluate Urgency & Threatening Language
    for pattern, label, points in URGENCY_PATTERNS:
        matches = re.findall(pattern, combined_content, re.IGNORECASE)
        if matches:
            result.is_urgent = True
            result.findings.append({
                "indicator_name": f"Urgency Indicator: {label}",
                "severity": "HIGH",
                "category": "CONTENT",
                "observed_evidence": f"Found phrase matching: '{matches[0]}'",
                "explanation": "Threat actors use urgent deadlines or fear of negative consequences to manipulate targets into bypassing standard verification protocols.",
                "source": "Content Heuristic Engine",
                "confidence": "HIGH",
                "recommended_step": "Verify communication via independent out-of-band channel before acting.",
                "points_added": points
            })
            result.mitre_techniques.append({
                "id": "T1204",
                "name": "User Execution",
                "description": "Adversaries rely on emotional urgency to prompt the user to execute links or attachments."
            })
            break  # Avoid double-counting within same urgency category

    # 2. Evaluate Credential Harvesting Patterns
    for pattern, label, points in CREDENTIAL_HARVEST_PATTERNS:
        matches = re.findall(pattern, combined_content, re.IGNORECASE)
        if matches:
            result.is_credential_harvest = True
            result.findings.append({
                "indicator_name": f"Credential Harvest Lure: {label}",
                "severity": "CRITICAL",
                "category": "CONTENT",
                "observed_evidence": f"Matched pattern: '{matches[0]}'",
                "explanation": "The email prompts the recipient to enter, verify, or reset credentials or payment details. Standard legitimate services do not request credentials via unsolicited emails.",
                "source": "Content Heuristic Engine",
                "confidence": "HIGH",
                "recommended_step": "Do NOT enter credentials on any linked pages. Reset credentials immediately if already submitted.",
                "points_added": points
            })
            result.mitre_techniques.append({
                "id": "T1566.002",
                "name": "Spearphishing Link",
                "description": "Adversaries send spearphishing emails with malicious links designed to capture employee credentials."
            })
            break

    # 3. Evaluate Financial & BEC Fraud Patterns
    for pattern, label, points in FINANCIAL_BEC_PATTERNS:
        matches = re.findall(pattern, combined_content, re.IGNORECASE)
        if matches:
            result.is_financial_bec = True
            result.findings.append({
                "indicator_name": f"Financial / BEC Pattern: {label}",
                "severity": "HIGH",
                "category": "CONTENT",
                "observed_evidence": f"Matched financial request: '{matches[0]}'",
                "explanation": "Message requests sensitive wire transfer, payroll adjustments, or gift card purchases. Frequent indicator of CEO Fraud or Business Email Compromise.",
                "source": "BEC Heuristic Engine",
                "confidence": "HIGH",
                "recommended_step": "Implement dual-analyst phone verification for any financial transfers or banking changes.",
                "points_added": points
            })
            break

    # 4. Attachment Analysis
    for att in email_obj.attachments:
        fname = att["filename"].lower()
        parts = fname.split(".")

        # Double extension check (e.g. invoice.pdf.exe)
        if len(parts) >= 3:
            penultimate = parts[-2]
            final_ext = parts[-1]
            if penultimate in ("pdf", "docx", "xlsx", "txt", "jpg", "png") and final_ext in DANGEROUS_EXTENSIONS:
                result.has_dangerous_attachment = True
                result.findings.append({
                    "indicator_name": f"Double Extension Concealment ({fname})",
                    "severity": "CRITICAL",
                    "category": "ATTACHMENT",
                    "observed_evidence": f"Attachment '{fname}' disguises a '.{final_ext}' executable as a '.{penultimate}' document.",
                    "explanation": "Threat actors append harmless extensions to deceive users on systems where file extensions are hidden by default.",
                    "source": "Attachment Forensics",
                    "confidence": "HIGH",
                    "recommended_step": "Isolate file; submit SHA-256 to sandbox; do NOT execute.",
                    "points_added": 35
                })
                result.mitre_techniques.append({
                    "id": "T1036.007",
                    "name": "Double File Extension",
                    "description": "Adversaries may use double extensions to disguise malicious executable files as benign document types."
                })

        # Check dangerous file extension
        ext = parts[-1] if len(parts) > 1 else ""
        if ext in DANGEROUS_EXTENSIONS:
            desc, sev, pts = DANGEROUS_EXTENSIONS[ext]
            result.has_dangerous_attachment = True
            result.findings.append({
                "indicator_name": f"High-Risk Attachment Type (.{ext})",
                "severity": sev,
                "category": "ATTACHMENT",
                "observed_evidence": f"Attachment '{att['filename']}' ({desc}) - SHA256: {att['sha256']}",
                "explanation": f"File type '.{ext}' can execute arbitrary code upon opening without sandbox protection.",
                "source": "Attachment Forensics",
                "confidence": "HIGH",
                "recommended_step": "Quarantine email and block payload hash on endpoint EDR agents.",
                "points_added": pts
            })
            result.mitre_techniques.append({
                "id": "T1566.001",
                "name": "Spearphishing Attachment",
                "description": "Adversaries attach weaponized files to emails to compromise victim systems upon execution."
            })

    # Deduplicate MITRE techniques
    unique_mitre = []
    seen_ids = set()
    for tech in result.mitre_techniques:
        if tech["id"] not in seen_ids:
            seen_ids.add(tech["id"])
            unique_mitre.append(tech)
    result.mitre_techniques = unique_mitre

    # Executive summary synthesis
    summary_parts = []
    if result.is_credential_harvest:
        summary_parts.append("active credential harvesting lures")
    if result.is_urgent:
        summary_parts.append("manufactured urgency coercions")
    if result.is_financial_bec:
        summary_parts.append("unsolicited financial disbursement instructions")
    if result.has_dangerous_attachment:
        summary_parts.append("high-risk weaponized attachment payloads")

    if summary_parts:
        result.summary_text = f"Content analysis identified {', '.join(summary_parts)}."
    else:
        result.summary_text = "No prominent phishing keywords, urgency triggers, or dangerous attachments detected in email body."

    return result
