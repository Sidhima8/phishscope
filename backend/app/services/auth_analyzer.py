import re
import dns.resolver
from typing import Dict, Any, List, Tuple
from app.services.email_parser import ParsedEmail

# Well-known brands and their genuine primary domains
TOP_BRANDS = {
    "microsoft": ["microsoft.com", "office.com", "office365.com", "microsoftonline.com", "azure.com", "live.com", "outlook.com"],
    "google": ["google.com", "gmail.com", "googlemail.com", "workspace.google.com"],
    "apple": ["apple.com", "icloud.com", "me.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "aws.amazon.com"],
    "paypal": ["paypal.com", "paypal.co.uk"],
    "netflix": ["netflix.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "dropbox": ["dropbox.com", "dropboxmail.com"],
    "chase": ["chase.com", "jpmorgan.com"],
    "bank of america": ["bankofamerica.com", "bofa.com"],
    "wellsfargo": ["wellsfargo.com"],
    "dhl": ["dhl.com", "dhl.de"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "facebook": ["facebook.com", "meta.com", "facebookmail.com"],
    "linkedin": ["linkedin.com"],
    "zoom": ["zoom.us"],
}

# Homoglyph character substitutions (Cyrillic / Greek / Numbers -> Latin)
HOMOGLYPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
    '0': 'o', '1': 'l', '3': 'e', '5': 's', '8': 'b', 'vv': 'w'
}


def normalize_homoglyphs(domain: str) -> str:
    """Normalize common homoglyphs to ASCII equivalents for comparison."""
    normalized = []
    for char in domain.lower():
        normalized.append(HOMOGLYPH_MAP.get(char, char))
    return "".join(normalized)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def check_lookalike_domain(domain: str) -> Tuple[bool, str, str]:
    """
    Check if a domain is a typo-squatted or lookalike variation of a top brand.
    Returns: (is_lookalike, target_brand, reason)
    """
    if not domain:
        return False, "", ""
    
    clean_domain = domain.lower().strip()
    domain_base = clean_domain.split(".")[0]
    normalized_full = normalize_homoglyphs(clean_domain)
    normalized_base = normalize_homoglyphs(domain_base)
    tokens = domain_base.split("-")

    for brand, genuine_domains in TOP_BRANDS.items():
        # If it's already one of the genuine domains, it's not a lookalike
        if clean_domain in genuine_domains or any(clean_domain.endswith("." + gd) for gd in genuine_domains):
            continue

        brand_base = brand.replace(" ", "")

        # 1. Direct homoglyph check on full base
        if normalized_base == brand_base and domain_base != brand_base:
            return True, brand, f"Domain '{domain}' uses homoglyphs to impersonate genuine brand '{brand}'"

        # 2. Check each hyphenated token for exact match after homoglyph normalization (e.g. paypa1-secure -> paypal)
        for tok in tokens:
            norm_tok = normalize_homoglyphs(tok)
            if norm_tok == brand_base:
                return True, brand, f"Domain '{domain}' contains lookalike token '{tok}' impersonating brand '{brand}'"
            dist = levenshtein_distance(tok, brand_base)
            if 1 <= dist <= 2 and len(brand_base) >= 5:
                return True, brand, f"Domain '{domain}' contains typo-squatted token '{tok}' (distance {dist} from '{brand_base}')"

        # 3. Levenshtein edit distance check on full base
        dist = levenshtein_distance(domain_base, brand_base)
        if 1 <= dist <= 2 and len(brand_base) >= 5:
            return True, brand, f"Domain '{domain}' has Levenshtein distance of {dist} from '{brand_base}' (Typo-squatting)"

        # 4. Brand name embedded in normalized domain or unauthorized subdomain
        if brand_base in normalized_full:
            return True, brand, f"Domain '{domain}' contains protected brand '{brand}' in an unauthorized domain"

    return False, "", ""


class AuthAnalysisResult:
    def __init__(self):
        self.spf_recorded: str = "none"
        self.spf_dns_found: bool = False
        self.spf_dns_record: str = ""
        self.spf_verdict: str = "NEUTRAL"
        
        self.dkim_recorded: str = "none"
        self.dkim_signature_found: bool = False
        self.dkim_selector: str = ""
        self.dkim_domain: str = ""
        self.dkim_dns_key_found: bool = False
        self.dkim_verdict: str = "NEUTRAL"

        self.dmarc_recorded: str = "none"
        self.dmarc_dns_found: bool = False
        self.dmarc_dns_record: str = ""
        self.dmarc_policy: str = "none"
        self.dmarc_verdict: str = "NEUTRAL"

        self.spf_alignment: bool = False
        self.dkim_alignment: bool = False

        self.reply_to_mismatch: bool = False
        self.return_path_mismatch: bool = False
        self.display_name_spoofing: bool = False
        self.spoofed_brand: str = ""
        self.lookalike_domain_detected: bool = False
        self.lookalike_brand: str = ""

        self.findings: List[Dict[str, Any]] = []
        self.summary_dict: Dict[str, Any] = {}


def analyze_email_authentication(email_obj: ParsedEmail) -> AuthAnalysisResult:
    result = AuthAnalysisResult()
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0

    # 1. Parse Recorded Headers (Authentication-Results & Received-SPF)
    auth_header = email_obj.headers_dict.get("authentication-results", "")
    if isinstance(auth_header, list):
        auth_header = " ".join([str(h) for h in auth_header])
    auth_str = str(auth_header).lower()

    received_spf = email_obj.headers_dict.get("received-spf", "")
    if isinstance(received_spf, list):
        received_spf = " ".join([str(h) for h in received_spf])
    spf_header_str = str(received_spf).lower()

    # SPF Recorded check
    if "spf=pass" in auth_str or spf_header_str.startswith("pass"):
        result.spf_recorded = "pass"
        result.spf_verdict = "PASS"
    elif "spf=fail" in auth_str or spf_header_str.startswith("fail"):
        result.spf_recorded = "fail"
        result.spf_verdict = "FAIL"
    elif "spf=softfail" in auth_str or spf_header_str.startswith("softfail"):
        result.spf_recorded = "softfail"
        result.spf_verdict = "SOFTFAIL"
    elif "spf=neutral" in auth_str or spf_header_str.startswith("neutral"):
        result.spf_recorded = "neutral"
        result.spf_verdict = "NEUTRAL"
    elif "spf=none" in auth_str or spf_header_str.startswith("none"):
        result.spf_recorded = "none"
        result.spf_verdict = "NONE"

    # DKIM Recorded check
    if "dkim=pass" in auth_str:
        result.dkim_recorded = "pass"
        result.dkim_verdict = "PASS"
    elif "dkim=fail" in auth_str:
        result.dkim_recorded = "fail"
        result.dkim_verdict = "FAIL"

    # DMARC Recorded check
    if "dmarc=pass" in auth_str:
        result.dmarc_recorded = "pass"
        result.dmarc_verdict = "PASS"
    elif "dmarc=fail" in auth_str:
        result.dmarc_recorded = "fail"
        result.dmarc_verdict = "FAIL"

    # 2. Check DKIM Signature in headers
    dkim_sig = email_obj.headers_dict.get("dkim-signature", "")
    if isinstance(dkim_sig, list):
        dkim_sig = str(dkim_sig[0])
    if dkim_sig:
        result.dkim_signature_found = True
        s_match = re.search(r'\bs=([^;\s]+)', dkim_sig)
        d_match = re.search(r'\bd=([^;\s]+)', dkim_sig)
        if s_match:
            result.dkim_selector = s_match.group(1).strip()
        if d_match:
            result.dkim_domain = d_match.group(1).strip().lower()

    # 3. Independent DNS Checks for Sender Domain
    sender_domain = email_obj.from_domain
    if sender_domain:
        # Independent SPF TXT record query
        try:
            answers = resolver.resolve(sender_domain, "TXT")
            for rdata in answers:
                txt_str = "".join([part.decode("utf-8", errors="ignore") for part in rdata.strings])
                if txt_str.startswith("v=spf1"):
                    result.spf_dns_found = True
                    result.spf_dns_record = txt_str
                    break
        except Exception:
            result.spf_dns_found = False

        # Independent DMARC query on _dmarc.<sender_domain>
        try:
            dmarc_host = f"_dmarc.{sender_domain}"
            answers = resolver.resolve(dmarc_host, "TXT")
            for rdata in answers:
                txt_str = "".join([part.decode("utf-8", errors="ignore") for part in rdata.strings])
                if "v=dmarc1" in txt_str.lower():
                    result.dmarc_dns_found = True
                    result.dmarc_dns_record = txt_str
                    p_match = re.search(r'\bp=([^;\s]+)', txt_str, re.IGNORECASE)
                    if p_match:
                        result.dmarc_policy = p_match.group(1).lower()
                    break
        except Exception:
            result.dmarc_dns_found = False

        # Independent DKIM DNS public key query if selector & domain are present
        if result.dkim_selector and result.dkim_domain:
            try:
                dkim_host = f"{result.dkim_selector}._domainkey.{result.dkim_domain}"
                dkim_answers = resolver.resolve(dkim_host, "TXT")
                for rdata in dkim_answers:
                    txt_str = "".join([part.decode("utf-8", errors="ignore") for part in rdata.strings])
                    if "v=dkim1" in txt_str.lower() or "p=" in txt_str.lower():
                        result.dkim_dns_key_found = True
                        break
            except Exception:
                result.dkim_dns_key_found = False

    # 4. Check Alignment
    if sender_domain and result.dkim_domain:
        if sender_domain == result.dkim_domain or sender_domain.endswith("." + result.dkim_domain) or result.dkim_domain.endswith("." + sender_domain):
            result.dkim_alignment = True

    if sender_domain and email_obj.return_path_domain:
        if sender_domain == email_obj.return_path_domain or sender_domain.endswith("." + email_obj.return_path_domain):
            result.spf_alignment = True

    # 5. Header Mismatches (From vs Reply-To & From vs Return-Path)
    if email_obj.from_domain and email_obj.reply_to_domain:
        if email_obj.from_domain != email_obj.reply_to_domain:
            result.reply_to_mismatch = True
            result.findings.append({
                "indicator_name": "Reply-To Domain Mismatch",
                "severity": "HIGH",
                "category": "HEADER",
                "observed_evidence": f"From: {email_obj.from_email} (domain: {email_obj.from_domain}) vs Reply-To: {email_obj.reply_to_email} (domain: {email_obj.reply_to_domain})",
                "explanation": "The Reply-To address redirects replies to a different domain than the sender. This is a common tactic in Business Email Compromise (BEC) and phishing campaigns.",
                "source": "Header Authentication Analyzer",
                "confidence": "HIGH",
                "recommended_step": "Inspect Reply-To domain history and block suspicious reply-to destinations.",
                "points_added": 22
            })

    if email_obj.from_domain and email_obj.return_path_domain:
        if email_obj.from_domain != email_obj.return_path_domain:
            result.return_path_mismatch = True

    # 6. Display Name Spoofing
    from_name_lower = email_obj.from_name.lower()
    for brand, genuine_domains in TOP_BRANDS.items():
        if brand in from_name_lower:
            # Check if actual domain is genuine
            is_genuine = any(email_obj.from_domain == gd or email_obj.from_domain.endswith("." + gd) for gd in genuine_domains)
            if not is_genuine and email_obj.from_domain:
                result.display_name_spoofing = True
                result.spoofed_brand = brand.title()
                result.findings.append({
                    "indicator_name": f"Display Name Brand Impersonation ({brand.title()})",
                    "severity": "CRITICAL",
                    "category": "HEADER",
                    "observed_evidence": f"From Display Name: '{email_obj.from_name}' mentions '{brand.title()}', but sender address is '{email_obj.from_email}' (domain: {email_obj.from_domain})",
                    "explanation": f"The sender configured their display name to pose as '{brand.title()}' while using an unrelated domain '{email_obj.from_domain}'. Highly characteristic of targeted credential phishing.",
                    "source": "Display Name Analyzer",
                    "confidence": "HIGH",
                    "recommended_step": f"Quarantine email and warn users about spoofed {brand.title()} correspondence.",
                    "points_added": 30
                })
                break

    # 7. Lookalike / Typo-squatted Domain Check
    if sender_domain:
        is_lookalike, lookalike_brand, reason = check_lookalike_domain(sender_domain)
        if is_lookalike:
            result.lookalike_domain_detected = True
            result.lookalike_brand = lookalike_brand
            result.findings.append({
                "indicator_name": f"Typo-Squatted Sender Domain ({lookalike_brand.title()})",
                "severity": "CRITICAL",
                "category": "HEADER",
                "observed_evidence": f"Sender domain: '{sender_domain}'. {reason}",
                "explanation": f"Domain closely mimics legitimate brand '{lookalike_brand.title()}' via homoglyphs or edit-distance variation.",
                "source": "Typo-Squatting Detection Engine",
                "confidence": "HIGH",
                "recommended_step": "Block sender domain at mail gateway and register domain indicator for threat hunting.",
                "points_added": 35
            })

    # 8. Authentication Failures Findings
    if result.spf_verdict == "FAIL":
        result.findings.append({
            "indicator_name": "SPF Authentication Failure",
            "severity": "HIGH",
            "category": "AUTH",
            "observed_evidence": f"Recorded SPF verdict: FAIL (Received-SPF / Authentication-Results)",
            "explanation": "The transmitting mail server's IP address was not authorized by the sender domain's SPF record.",
            "source": "SPF Verification Engine",
            "confidence": "HIGH",
            "recommended_step": "Verify sender IP against authorized MX infrastructure; consider quarantine if DMARC fails.",
            "points_added": 18
        })
    elif not result.spf_dns_found and sender_domain:
        result.findings.append({
            "indicator_name": "Missing SPF Record on Sender Domain",
            "severity": "MEDIUM",
            "category": "AUTH",
            "observed_evidence": f"No valid v=spf1 TXT record found for domain: {sender_domain}",
            "explanation": "The sender domain lacks SPF publishing, allowing arbitrary external hosts to forge mail claiming to originate from this domain.",
            "source": "DNS Resolver",
            "confidence": "MEDIUM",
            "recommended_step": "Advise domain administrator to deploy SPF policies.",
            "points_added": 8
        })

    if result.dkim_verdict == "FAIL":
        result.findings.append({
            "indicator_name": "DKIM Cryptographic Signature Failure",
            "severity": "HIGH",
            "category": "AUTH",
            "observed_evidence": "Recorded DKIM signature failed verification or was corrupted in transit.",
            "explanation": "DKIM signature validation failed, indicating header alteration, content tampering, or key mismatch.",
            "source": "DKIM Verification Engine",
            "confidence": "HIGH",
            "recommended_step": "Inspect raw message headers for tampering in mail relays.",
            "points_added": 18
        })

    if result.dmarc_verdict == "FAIL":
        result.findings.append({
            "indicator_name": "DMARC Alignment Failure",
            "severity": "HIGH",
            "category": "AUTH",
            "observed_evidence": f"DMARC status: FAIL (Policy: {result.dmarc_policy})",
            "explanation": "Message failed DMARC policy check; neither SPF nor DKIM passed in alignment with the From header domain.",
            "source": "DMARC Verification Engine",
            "confidence": "HIGH",
            "recommended_step": "Enforce receiving server policy rejection if p=reject or quarantine.",
            "points_added": 20
        })
    elif not result.dmarc_dns_found and sender_domain:
        result.findings.append({
            "indicator_name": "No DMARC Record Published",
            "severity": "LOW",
            "category": "AUTH",
            "observed_evidence": f"No _dmarc.{sender_domain} record published in DNS",
            "explanation": "Domain does not publish DMARC policy, reducing protection against domain spoofing.",
            "source": "DNS Resolver",
            "confidence": "MEDIUM",
            "recommended_step": "Encourage sender domain to implement DMARC enforcement.",
            "points_added": 4
        })

    # Summary dictionary for database persistence and UI rendering
    result.summary_dict = {
        "spf": {
            "recorded": result.spf_recorded,
            "verdict": result.spf_verdict,
            "dns_record_found": result.spf_dns_found,
            "dns_record": result.spf_dns_record,
            "alignment": result.spf_alignment,
        },
        "dkim": {
            "recorded": result.dkim_recorded,
            "verdict": result.dkim_verdict,
            "signature_present": result.dkim_signature_found,
            "selector": result.dkim_selector,
            "domain": result.dkim_domain,
            "dns_key_found": result.dkim_dns_key_found,
            "alignment": result.dkim_alignment,
        },
        "dmarc": {
            "recorded": result.dmarc_recorded,
            "verdict": result.dmarc_verdict,
            "dns_record_found": result.dmarc_dns_found,
            "dns_record": result.dmarc_dns_record,
            "policy": result.dmarc_policy,
        },
        "mismatches": {
            "reply_to_mismatch": result.reply_to_mismatch,
            "return_path_mismatch": result.return_path_mismatch,
            "display_name_spoofing": result.display_name_spoofing,
            "spoofed_brand": result.spoofed_brand,
            "lookalike_domain": result.lookalike_domain_detected,
            "lookalike_brand": result.lookalike_brand,
        }
    }

    return result
