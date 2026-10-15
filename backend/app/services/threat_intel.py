import time
import base64
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import httpx
import dns.resolver
from app.core.config import settings

# In-memory LRU / TTL cache for threat intel results
# Key format: f"{provider}:{target_type}:{target_value}"
_INTEL_CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_TTL_SECONDS = 3600  # 1 hour


def _get_cached(cache_key: str) -> Optional[Dict[str, Any]]:
    cached = _INTEL_CACHE.get(cache_key)
    if cached and time.time() - cached["cached_at"] < CACHE_TTL_SECONDS:
        res = cached["data"].copy()
        res["cached"] = True
        return res
    return None


def _set_cached(cache_key: str, data: Dict[str, Any]):
    _INTEL_CACHE[cache_key] = {
        "cached_at": time.time(),
        "data": data
    }


class ThreatIntelService:
    def __init__(self):
        self.vt_api_key = settings.VIRUSTOTAL_API_KEY
        self.urlhaus_api_key = settings.URLHAUS_API_KEY

    async def query_virustotal_url(self, url: str) -> Dict[str, Any]:
        """Query VirusTotal API v3 for URL reputation."""
        if not self.vt_api_key:
            return {
                "provider": "VirusTotal",
                "status": "not_configured",
                "message": "VirusTotal API key not configured in environment (VIRUSTOTAL_API_KEY)",
                "reputation": "unknown"
            }

        cache_key = f"vt:url:{url}"
        cached = _get_cached(cache_key)
        if cached:
            return cached

        # VT API v3 uses base64 URL identifier without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        headers = {"x-apikey": self.vt_api_key}
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)

                    reputation = "clean"
                    if malicious > 0:
                        reputation = "malicious"
                    elif suspicious > 0:
                        reputation = "suspicious"

                    result = {
                        "provider": "VirusTotal",
                        "status": "operational",
                        "reputation": reputation,
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                        "harmless_count": harmless,
                        "categories": data.get("categories", {}),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                    _set_cached(cache_key, result)
                    return result
                elif resp.status_code == 404:
                    return {
                        "provider": "VirusTotal",
                        "status": "operational",
                        "reputation": "unknown",
                        "message": "Indicator not previously scanned in VirusTotal dataset",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                elif resp.status_code == 429:
                    return {
                        "provider": "VirusTotal",
                        "status": "rate_limited",
                        "message": "VirusTotal API rate limit exceeded",
                        "reputation": "inconclusive"
                    }
                else:
                    return {
                        "provider": "VirusTotal",
                        "status": "error",
                        "message": f"VirusTotal returned HTTP {resp.status_code}",
                        "reputation": "inconclusive"
                    }
        except Exception as e:
            return {
                "provider": "VirusTotal",
                "status": "error",
                "message": f"Connection error querying VirusTotal: {str(e)}",
                "reputation": "inconclusive"
            }

    async def query_urlhaus(self, target_url: str) -> Dict[str, Any]:
        """Query URLhaus (abuse.ch) for known malware / phishing URLs."""
        cache_key = f"urlhaus:url:{target_url}"
        cached = _get_cached(cache_key)
        if cached:
            return cached

        endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        data_payload = {"url": target_url}
        headers = {}
        if self.urlhaus_api_key:
            headers["Auth-Key"] = self.urlhaus_api_key

        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.post(endpoint, data=data_payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    query_status = data.get("query_status", "no_results")
                    if query_status == "ok":
                        result = {
                            "provider": "URLhaus",
                            "status": "operational",
                            "reputation": "malicious",
                            "urlhaus_status": data.get("url_status"),
                            "threat": data.get("threat"),
                            "tags": data.get("tags", []),
                            "date_added": data.get("date_added"),
                            "reporter": data.get("reporter"),
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                    else:
                        result = {
                            "provider": "URLhaus",
                            "status": "operational",
                            "reputation": "clean",
                            "message": "No active threat intelligence entry in URLhaus database",
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        }
                    _set_cached(cache_key, result)
                    return result
                else:
                    return {
                        "provider": "URLhaus",
                        "status": "error",
                        "message": f"URLhaus API returned HTTP {resp.status_code}",
                        "reputation": "inconclusive"
                    }
        except Exception as e:
            return {
                "provider": "URLhaus",
                "status": "error",
                "message": f"URLhaus connection timeout or error: {str(e)}",
                "reputation": "inconclusive"
            }

    async def query_rdap_domain(self, domain: str) -> Dict[str, Any]:
        """Query RDAP for domain registration age and registrar details."""
        if not domain or "." not in domain:
            return {
                "provider": "RDAP",
                "status": "error",
                "message": "Invalid domain name",
                "reputation": "unknown"
            }

        cache_key = f"rdap:domain:{domain}"
        cached = _get_cached(cache_key)
        if cached:
            return cached

        endpoint = f"https://rdap.org/domain/{domain.strip().lower()}"
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.get(endpoint, headers={"Accept": "application/rdap+json"})
                if resp.status_code == 200:
                    data = resp.json()
                    events = data.get("events", [])
                    reg_date_str = None
                    for ev in events:
                        if ev.get("eventAction") in ("registration", "created"):
                            reg_date_str = ev.get("eventDate")
                            break

                    age_days = None
                    is_new_domain = False
                    if reg_date_str:
                        try:
                            # Format usually 2024-01-15T00:00:00Z
                            clean_dt_str = reg_date_str.replace("Z", "+00:00")
                            reg_dt = datetime.fromisoformat(clean_dt_str)
                            now_dt = datetime.now(timezone.utc)
                            delta = now_dt - reg_dt
                            age_days = delta.days
                            if age_days < 30:
                                is_new_domain = True
                        except Exception:
                            pass

                    registrar_name = "Unknown"
                    for entity in data.get("entities", []):
                        if "registrar" in entity.get("roles", []):
                            vcard = entity.get("vcardArray", [])
                            if len(vcard) > 1:
                                for item in vcard[1]:
                                    if item[0] == "fn":
                                        registrar_name = item[3]
                                        break

                    result = {
                        "provider": "RDAP",
                        "status": "operational",
                        "domain": domain,
                        "registrar": registrar_name,
                        "registration_date": reg_date_str,
                        "age_days": age_days,
                        "is_newly_registered": is_new_domain,
                        "reputation": "suspicious" if is_new_domain else "clean",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                    _set_cached(cache_key, result)
                    return result
                else:
                    return {
                        "provider": "RDAP",
                        "status": "operational",
                        "reputation": "unknown",
                        "message": f"RDAP data not found for domain (HTTP {resp.status_code})",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
        except Exception as e:
            return {
                "provider": "RDAP",
                "status": "error",
                "message": f"RDAP query error: {str(e)}",
                "reputation": "unknown"
            }

    def resolve_dns_records(self, domain: str) -> Dict[str, Any]:
        """Perform DNS lookups for MX, A, and TXT records using dnspython."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.5
        resolver.lifetime = 2.5

        results = {
            "provider": "DNS Resolver",
            "domain": domain,
            "mx_records": [],
            "a_records": [],
            "txt_records": [],
            "status": "operational",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        try:
            mx_ans = resolver.resolve(domain, "MX")
            results["mx_records"] = [str(r.exchange).rstrip(".") for r in mx_ans]
        except Exception:
            pass

        try:
            a_ans = resolver.resolve(domain, "A")
            results["a_records"] = [str(r) for r in a_ans]
        except Exception:
            pass

        try:
            txt_ans = resolver.resolve(domain, "TXT")
            results["txt_records"] = ["".join([p.decode("utf-8", errors="ignore") for p in r.strings]) for r in txt_ans]
        except Exception:
            pass

        return results


threat_intel_service = ThreatIntelService()
