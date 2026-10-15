import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import httpx
from typing import List, Dict, Any, Tuple, Optional
from app.core.ssrf import validate_url_for_ssrf
from app.services.auth_analyzer import check_lookalike_domain


URL_REGEX = re.compile(
    r'(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s`"<>{}|\^]{2,}|https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?::[0-9]+)?(?:\/[^\s`"<>{}|\^]*)?)',
    re.IGNORECASE
)

# Common URL shortener services
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly", "cutt.ly",
    "rb.gy", "rebrand.ly", "shorturl.at", "tiny.cc", "goo.gl", "bl.ink", "lnkd.in"
}

# Suspicious TLDs frequently abused in commodity phishing
SUSPICIOUS_TLDS = {
    "xyz", "top", "buzz", "club", "tk", "ml", "ga", "cf", "gq", "work", "loan",
    "click", "cam", "fit", "surf", "rest", "bar", "icu", "country", "stream"
}

# Suspicious keywords in subdomains or paths
PHISH_KEYWORDS = [
    "verify", "login", "account", "security", "update", "banking", "secure",
    "confirm", "signin", "support", "billing", "authenticate", "portal", "recovery", "password"
]


def defang_url(url: str) -> str:
    """Safely defang URL to prevent accidental clicking: http://foo.com -> hxxp[://]foo[.]com"""
    if not url:
        return ""
    defanged = url.replace("http://", "hxxp[://]").replace("https://", "hxxps[://]")
    defanged = defanged.replace(".", "[.]")
    return defanged


def refang_url(defanged_url: str) -> str:
    """Convert defanged URL back to standard URL."""
    if not defanged_url:
        return ""
    return defanged_url.replace("hxxps[://]", "https://").replace("hxxp[://]", "http://").replace("[.]", ".")


class ExtractedURL:
    def __init__(self, raw_url: str, anchor_text: str = ""):
        self.raw_url = raw_url.strip()
        self.defanged_url = defang_url(self.raw_url)
        self.anchor_text = anchor_text.strip()
        self.parsed = urlparse(self.raw_url)
        self.hostname = (self.parsed.hostname or "").lower()
        self.scheme = self.parsed.scheme.lower()
        self.path = self.parsed.path
        
        self.is_shortener = False
        self.is_ip_host = False
        self.is_lookalike = False
        self.lookalike_brand = ""
        self.is_suspicious_tld = False
        self.has_phish_keywords = False
        self.anchor_mismatch = False
        self.mismatch_details = ""
        self.subdomain_count = 0
        self.flags: List[str] = []
        self.redirect_chain: List[str] = []


def extract_urls_from_content(body_text: str, body_html: str) -> List[ExtractedURL]:
    """Extract URLs from both plain text and HTML bodies with anchor text preservation."""
    urls_dict: Dict[str, ExtractedURL] = {}

    # 1. Parse HTML if available for anchor tags & mismatches
    if body_html:
        try:
            soup = BeautifulSoup(body_html, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                if href.startswith(("http://", "https://")):
                    text = a_tag.get_text().strip()
                    if href not in urls_dict:
                        urls_dict[href] = ExtractedURL(href, anchor_text=text)

            # Also check iframe and img sources
            for tag in soup.find_all(["iframe", "img"], src=True):
                src = tag["src"].strip()
                if src.startswith(("http://", "https://")) and src not in urls_dict:
                    urls_dict[src] = ExtractedURL(src, anchor_text="[Embedded Media]")
        except Exception:
            pass

    # 2. Extract plain text URLs via regex
    all_text = f"{body_text}\n{body_html}"
    found_urls = URL_REGEX.findall(all_text)
    for raw in found_urls:
        clean = raw.rstrip(".,;)>]\"'")
        if clean not in urls_dict:
            urls_dict[clean] = ExtractedURL(clean)

    return list(urls_dict.values())


def inspect_url(extracted: ExtractedURL) -> Tuple[ExtractedURL, List[Dict[str, Any]]]:
    """Inspect URL structure, flags, shorteners, IP host, lookalike and anchor mismatches."""
    findings = []
    host = extracted.hostname

    if not host:
        return extracted, findings

    # Check if host is direct raw IP
    ip_match = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host)
    if ip_match:
        extracted.is_ip_host = True
        extracted.flags.append("IP-based Host")
        findings.append({
            "indicator_name": "Direct IP-Based URL Destination",
            "severity": "HIGH",
            "category": "URL",
            "observed_evidence": f"URL uses raw IP instead of domain name: {extracted.defanged_url}",
            "explanation": "Legitimate enterprise services rarely use raw IP addresses in email links. Threat actors frequently host phishing landing pages on raw VPS IP addresses to evade domain reputation filters.",
            "source": "URL Analyzer",
            "confidence": "HIGH",
            "recommended_step": "Block destination IP on perimeter firewall and web proxy.",
            "points_added": 20
        })

    # Check URL Shortener
    if host in SHORTENERS or any(host.endswith("." + s) for s in SHORTENERS):
        extracted.is_shortener = True
        extracted.flags.append("URL Shortener")
        findings.append({
            "indicator_name": "Obfuscated URL via Shortening Service",
            "severity": "MEDIUM",
            "category": "URL",
            "observed_evidence": f"Shortener detected: {host} ({extracted.defanged_url})",
            "explanation": "URL shorteners conceal the true destination host from the recipient and standard mail filters.",
            "source": "URL Analyzer",
            "confidence": "HIGH",
            "recommended_step": "Expand shortened URL through safe sandbox follower to reveal the final destination.",
            "points_added": 12
        })

    # Check TLD
    tld = host.split(".")[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        extracted.is_suspicious_tld = True
        extracted.flags.append(f"Suspicious TLD (.{tld})")
        findings.append({
            "indicator_name": f"High-Risk Top Level Domain (.{tld})",
            "severity": "MEDIUM",
            "category": "URL",
            "observed_evidence": f"Destination domain '{host}' uses high-abuse TLD .{tld}",
            "explanation": "Certain cheap or free TLDs exhibit disproportionately high abuse rates for disposable phishing kits.",
            "source": "TLD Reputation Engine",
            "confidence": "MEDIUM",
            "recommended_step": "Inspect web content and domain registration history.",
            "points_added": 10
        })

    # Check Subdomain Count & Phishing keywords in hostname
    subdomain_parts = host.split(".")
    extracted.subdomain_count = len(subdomain_parts)
    if len(subdomain_parts) >= 4:
        extracted.flags.append("Deep Subdomain Structure")
        findings.append({
            "indicator_name": "Excessive Subdomain Depth",
            "severity": "MEDIUM",
            "category": "URL",
            "observed_evidence": f"Hostname '{host}' contains {len(subdomain_parts)} subdomain levels",
            "explanation": "Adversaries create deep subdomains mimicking genuine services (e.g., login.microsoft.com.attacker.xyz) to deceive mobile and web users.",
            "source": "URL Analyzer",
            "confidence": "MEDIUM",
            "recommended_step": "Examine the apex domain rather than the prefixed subdomains.",
            "points_added": 10
        })

    for kw in PHISH_KEYWORDS:
        if kw in host.split(".")[0] or kw in extracted.path.lower():
            extracted.has_phish_keywords = True
            extracted.flags.append(f"Keyword: {kw}")

    # Check Lookalike / Typosquatting in URL Host
    is_lookalike, lookalike_brand, reason = check_lookalike_domain(host)
    if is_lookalike:
        extracted.is_lookalike = True
        extracted.lookalike_brand = lookalike_brand
        extracted.flags.append(f"Lookalike: {lookalike_brand}")
        findings.append({
            "indicator_name": f"Impersonated Brand in URL Host ({lookalike_brand.title()})",
            "severity": "CRITICAL",
            "category": "URL",
            "observed_evidence": f"Target host: '{host}'. {reason}",
            "explanation": f"URL hostname specifically mimics protected brand '{lookalike_brand.title()}'.",
            "source": "Typosquatting Engine",
            "confidence": "HIGH",
            "recommended_step": "Blacklist URL and alert users of spoofed portal.",
            "points_added": 28
        })

    # Check Anchor Text vs Destination Mismatch (Classic Phishing Technique!)
    if extracted.anchor_text:
        anchor_lower = extracted.anchor_text.lower()
        # If the visible anchor text looks like a legitimate domain or URL
        if re.search(r'https?:\/\/|[a-z0-9-]+\.(?:com|org|net|gov|edu)', anchor_lower):
            # Extract domain from visible text
            anchor_domains = re.findall(r'([a-z0-9-]+\.[a-z]{2,})', anchor_lower)
            if anchor_domains:
                visible_domain = anchor_domains[0]
                if visible_domain not in host and not host.endswith("." + visible_domain):
                    extracted.anchor_mismatch = True
                    extracted.mismatch_details = f"Visible link text displays '{extracted.anchor_text}' but links to '{host}'"
                    extracted.flags.append("Anchor Text Mismatch")
                    findings.append({
                        "indicator_name": "Anchor Text vs Destination Link Mismatch",
                        "severity": "CRITICAL",
                        "category": "URL",
                        "observed_evidence": f"User sees: '{extracted.anchor_text}', but browser is directed to '{extracted.defanged_url}'",
                        "explanation": "The visible anchor text displays a legitimate service or brand, but the underlying hyperlink points to an entirely different foreign destination. This is a primary deceptive phishing technique.",
                        "source": "HTML Structure Inspector",
                        "confidence": "HIGH",
                        "recommended_step": "Quarantine email and report phishing link destination.",
                        "points_added": 30
                    })

    return extracted, findings


async def expand_url_safely(target_url: str, max_hops: int = 5, timeout: float = 3.5) -> Dict[str, Any]:
    """
    Safely follow redirects up to max_hops with strict SSRF validation before every request.
    Never exposes internal network or cloud metadata.
    """
    history = [target_url]
    current_url = target_url
    final_url = target_url
    status_code = None
    abort_reason = None

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 (PhishScope Analyst Inspector)",
        "Accept": "*/*"
    }

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, verify=False) as client:
        for hop in range(max_hops):
            # 1. SSRF Check BEFORE sending request
            is_safe, reason = validate_url_for_ssrf(current_url)
            if not is_safe:
                abort_reason = f"SSRF Guard Abort: {reason}"
                break

            try:
                # Use HEAD request first to minimize network transfer
                resp = await client.head(current_url, headers=headers)
                # If HEAD returns 405 Method Not Allowed, try GET with stream to avoid full download
                if resp.status_code == 405:
                    resp = await client.get(current_url, headers=headers)
            except Exception as e:
                abort_reason = f"Connection error: {str(e)}"
                break

            status_code = resp.status_code

            # Check if redirect response (301, 302, 303, 307, 308)
            if status_code in (301, 302, 303, 307, 308) and "location" in resp.headers:
                next_url = urljoin(current_url, resp.headers["location"])
                history.append(next_url)
                current_url = next_url
                final_url = next_url
            else:
                # No more redirects
                final_url = current_url
                break

    return {
        "original_url": target_url,
        "final_url": final_url,
        "final_defanged": defang_url(final_url),
        "chain": [defang_url(u) for u in history],
        "hops_count": len(history) - 1,
        "last_status": status_code,
        "aborted": abort_reason is not None,
        "abort_reason": abort_reason,
    }
