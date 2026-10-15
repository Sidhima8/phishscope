import os
import pytest
from app.core.ssrf import validate_url_for_ssrf, is_ip_safe
from app.services.email_parser import parse_email_message
from app.services.auth_analyzer import analyze_email_authentication, check_lookalike_domain, normalize_homoglyphs
from app.services.url_analyzer import extract_urls_from_content, inspect_url, defang_url, refang_url
from app.services.content_analyzer import analyze_email_content
from app.services.risk_engine import calculate_risk_score
from app.services.report_generator import generate_case_pdf_report


def test_ssrf_protection_blocks_internal_and_metadata():
    """Verify that SSRF guard strictly blocks internal IPs, loopback, and cloud metadata."""
    # Cloud metadata endpoint
    safe, reason = is_ip_safe("169.254.169.254")
    assert not safe
    assert "Link-local" in reason or "Internal/Private" in reason or "Blocked network" in reason

    # Localhost loopback
    safe, reason = is_ip_safe("127.0.0.1")
    assert not safe

    # RFC 1918 Private networks
    assert not is_ip_safe("10.0.0.1")[0]
    assert not is_ip_safe("172.16.5.10")[0]
    assert not is_ip_safe("192.168.1.1")[0]

    # Non-routable broadcast/multicast
    assert not is_ip_safe("0.0.0.0")[0]
    assert not is_ip_safe("224.0.0.1")[0]

    # Public IP should pass
    safe, _ = is_ip_safe("93.184.216.34")  # example.com
    assert safe


def test_ssrf_url_validation():
    """Verify scheme and host validation for URLs."""
    # Invalid schemes
    assert not validate_url_for_ssrf("file:///etc/passwd")[0]
    assert not validate_url_for_ssrf("gopher://127.0.0.1:70")[0]

    # Metadata host
    assert not validate_url_for_ssrf("http://169.254.169.254/latest/meta-data")[0]
    assert not validate_url_for_ssrf("http://localhost:8000/api")[0]


def test_lookalike_domain_detection():
    """Verify homoglyph and Levenshtein typo-squatting detection."""
    # Direct typo-squatting (Levenshtein distance)
    is_lookalike, brand, reason = check_lookalike_domain("micros0ft.com")
    assert is_lookalike
    assert brand == "microsoft"

    is_lookalike, brand, _ = check_lookalike_domain("paypa1-secure.com")
    assert is_lookalike

    # Genuine domain must not be flagged
    is_lookalike, _, _ = check_lookalike_domain("microsoft.com")
    assert not is_lookalike

    is_lookalike, _, _ = check_lookalike_domain("paypal.com")
    assert not is_lookalike


def test_defang_and_refang_url():
    """Verify URL defanging and refanging for analyst safety."""
    url = "https://evil-phish.com/login.php?user=admin"
    defanged = defang_url(url)
    assert defanged == "hxxps[://]evil-phish[.]com/login[.]php?user=admin"
    
    refanged = refang_url(defanged)
    assert refanged == url


def test_email_parser_on_samples():
    """Verify email parser correctly extracts headers, hops and bodies from realistic .eml files."""
    samples_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")
    phish_path = os.path.join(samples_dir, "phish_m365_credential_harvest.eml")
    
    with open(phish_path, "rb") as f:
        raw_bytes = f.read()

    parsed = parse_email_message(raw_bytes)
    assert "Microsoft 365" in parsed.from_header
    assert parsed.from_domain == "micros0ft-account-verify.com"
    assert "Suspension Notice" in parsed.subject
    assert len(parsed.received_hops) > 0
    assert parsed.sha256_hash != ""


def test_auth_analyzer_detects_spoofing():
    """Verify authentication analyzer flags display name spoofing and SPF failures."""
    samples_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")
    phish_path = os.path.join(samples_dir, "phish_m365_credential_harvest.eml")
    
    with open(phish_path, "rb") as f:
        parsed = parse_email_message(f.read())

    auth_res = analyze_email_authentication(parsed)
    assert auth_res.spf_verdict == "FAIL"
    assert auth_res.display_name_spoofing
    assert auth_res.spoofed_brand == "Microsoft"
    assert auth_res.lookalike_domain_detected
    assert len(auth_res.findings) >= 2


def test_content_analyzer_urgency_and_harvest():
    """Verify content analysis detects urgency keywords and credential harvesting lures."""
    samples_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")
    phish_path = os.path.join(samples_dir, "phish_m365_credential_harvest.eml")
    
    with open(phish_path, "rb") as f:
        parsed = parse_email_message(f.read())

    content_res = analyze_email_content(parsed)
    assert content_res.is_urgent
    assert content_res.is_credential_harvest
    assert any(tech["id"] == "T1566.002" for tech in content_res.mitre_techniques)


def test_anchor_text_mismatch_detection():
    """Verify that HTML links where anchor text differs from actual href are flagged."""
    body_html = '<p>Click here to verify: <a href="http://185.220.101.5/steal">https://login.microsoftonline.com</a></p>'
    urls = extract_urls_from_content("", body_html)
    assert len(urls) >= 1
    
    inspected_list = [inspect_url(u) for u in urls]
    has_mismatch = any(inspected.anchor_mismatch for inspected, _ in inspected_list)
    assert has_mismatch


def test_risk_score_calculation():
    """Verify risk engine scoring, tiering and deduplication."""
    findings = [
        {"indicator_name": "Typo-Squatted Sender Domain", "severity": "CRITICAL", "category": "HEADER", "points_added": 35},
        {"indicator_name": "Display Name Brand Impersonation", "severity": "CRITICAL", "category": "HEADER", "points_added": 30},
        {"indicator_name": "Anchor Text vs Destination Link Mismatch", "severity": "CRITICAL", "category": "URL", "points_added": 30},
        {"indicator_name": "Credential Harvest Lure", "severity": "CRITICAL", "category": "CONTENT", "points_added": 24},
    ]
    result = calculate_risk_score(findings, total_checks_attempted=10, unavailable_count=1)
    assert result.risk_score >= 75
    assert result.risk_level == "CRITICAL"
    assert result.confidence == "HIGH"
    assert result.completed_checks == 9


def test_reportlab_pdf_generation():
    """Verify forensic PDF report renders without exception and outputs valid PDF magic bytes."""
    mock_case = {
        "case_number": "PS-TEST-001",
        "title": "Test Case",
        "subject": "Critical Phishing Test",
        "sender": "attacker@micros0ft.com",
        "file_hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "status": "NEEDS_REVIEW",
        "risk_score": 88,
        "risk_level": "CRITICAL",
        "confidence": "HIGH",
        "completed_checks": 8,
        "unavailable_checks": 1,
        "executive_summary": "High confidence targeted credential harvesting attempt.",
        "auth_summary": {
            "spf": {"recorded": "fail", "verdict": "FAIL", "dns_record_found": False, "alignment": False},
            "dkim": {"recorded": "none", "verdict": "NEUTRAL", "dns_key_found": False, "alignment": False},
            "dmarc": {"recorded": "fail", "verdict": "FAIL", "dns_record_found": False, "policy": "none"}
        },
        "findings": [
            {
                "indicator_name": "Typo-Squatted Domain",
                "severity": "CRITICAL",
                "points_added": 35,
                "observed_evidence": "micros0ft.com impersonating Microsoft",
                "source": "Typosquatting Engine",
                "explanation": "Homoglyph detected."
            }
        ],
        "indicators": [
            {
                "indicator_type": "URL",
                "defanged_value": "hxxp[://]micros0ft[.]com/login",
                "reputation": "MALICIOUS",
                "flags": ["Lookalike"]
            }
        ],
        "notes": [
            {
                "author_name": "Senior SOC Analyst",
                "action_type": "NOTE",
                "note_text": "Case flagged as active phishing campaign.",
                "created_at": "2026-10-15T10:00:00"
            }
        ]
    }

    pdf_bytes = generate_case_pdf_report(mock_case)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF")  # Standard PDF file header magic bytes
