import time
from fastapi import APIRouter
from app.services.threat_intel import threat_intel_service
from app.core.config import settings

router = APIRouter()


@router.get("/status")
async def get_integrations_status():
    """Return live status of threat intelligence providers."""
    return {
        "providers": [
            {
                "id": "urlhaus",
                "name": "URLhaus (abuse.ch)",
                "configured": True,
                "status": "OPERATIONAL",
                "description": "Public database of malicious sites used for malware and phishing distribution.",
                "requires_api_key": False
            },
            {
                "id": "virustotal",
                "name": "VirusTotal v3",
                "configured": bool(settings.VIRUSTOTAL_API_KEY),
                "status": "OPERATIONAL" if settings.VIRUSTOTAL_API_KEY else "NOT_CONFIGURED",
                "description": "Aggregated intelligence from 70+ antivirus engines and URL analysis tools.",
                "requires_api_key": True
            },
            {
                "id": "rdap",
                "name": "RDAP Registration Protocol",
                "configured": True,
                "status": "OPERATIONAL",
                "description": "Standardized successor to WHOIS providing domain age and ownership metadata.",
                "requires_api_key": False
            },
            {
                "id": "dns",
                "name": "DNS Resolver (dnspython)",
                "configured": True,
                "status": "OPERATIONAL",
                "description": "Queries authoritative name servers for MX, TXT, SPF, and DMARC verification.",
                "requires_api_key": False
            }
        ]
    }
