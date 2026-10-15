from typing import List, Dict, Any, Tuple


class RiskCalculationResult:
    def __init__(self):
        self.risk_score: int = 0
        self.risk_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
        self.confidence: str = "MEDIUM"  # HIGH, MEDIUM, LOW
        self.scored_findings: List[Dict[str, Any]] = []
        self.completed_checks: int = 0
        self.failed_checks: int = 0
        self.unavailable_checks: int = 0
        self.explanation: str = ""


def calculate_risk_score(
    all_findings: List[Dict[str, Any]],
    total_checks_attempted: int = 10,
    unavailable_count: int = 0
) -> RiskCalculationResult:
    """
    Explainable, weighted risk scoring engine.
    Deduplicates repeated indicators and caps category contributions.
    """
    res = RiskCalculationResult()
    res.unavailable_checks = unavailable_count
    
    # Category point caps to prevent single vector over-saturation
    category_caps = {
        "HEADER": 40,
        "AUTH": 35,
        "URL": 45,
        "CONTENT": 40,
        "ATTACHMENT": 50,
        "THREAT_INTEL": 45,
    }

    category_totals = {cat: 0 for cat in category_caps}
    seen_indicator_names = set()
    total_raw_points = 0
    res.scored_findings = []

    for f in all_findings:
        cat = f.get("category", "CONTENT").upper()
        name = f.get("indicator_name", "")
        pts = f.get("points_added", 0)

        # Dampen duplicate indicator penalties by 50%
        if name in seen_indicator_names:
            pts = int(pts * 0.5)
        seen_indicator_names.add(name)

        # Apply category cap
        current_cat_sum = category_totals.get(cat, 0)
        max_cat = category_caps.get(cat, 40)

        effective_pts = min(pts, max(0, max_cat - current_cat_sum))
        category_totals[cat] = current_cat_sum + effective_pts
        total_raw_points += effective_pts

        scored_item = f.copy()
        scored_item["effective_points"] = effective_pts
        res.scored_findings.append(scored_item)

    # Base score normalized and capped to [0, 100]
    final_score = min(100, max(0, total_raw_points))
    res.risk_score = final_score

    # Determine risk level
    if final_score >= 75:
        res.risk_level = "CRITICAL"
    elif final_score >= 50:
        res.risk_level = "HIGH"
    elif final_score >= 25:
        res.risk_level = "MEDIUM"
    else:
        res.risk_level = "LOW"

    # Count failed vs passed checks
    res.failed_checks = len([f for f in all_findings if f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")])
    res.completed_checks = max(0, total_checks_attempted - unavailable_count)

    # Determine confidence
    if res.completed_checks >= 8 and len(all_findings) > 0:
        res.confidence = "HIGH"
    elif res.completed_checks >= 5:
        res.confidence = "MEDIUM"
    else:
        res.confidence = "LOW"

    # Explanation summary
    crit_count = len([f for f in all_findings if f.get("severity") == "CRITICAL"])
    high_count = len([f for f in all_findings if f.get("severity") == "HIGH"])
    
    if res.risk_level == "CRITICAL":
        res.explanation = f"Critical risk score ({final_score}/100) driven by {crit_count} critical indicator(s) and {high_count} high-severity anomaly(s). Immediate quarantine and incident escalation recommended."
    elif res.risk_level == "HIGH":
        res.explanation = f"High risk score ({final_score}/100) indicates strong evidence of deceptive phishing techniques or spoofed origin. Analyst review required."
    elif res.risk_level == "MEDIUM":
        res.explanation = f"Medium risk score ({final_score}/100) with suspicious indicators detected. Email deviates from normal baseline; verification suggested."
    else:
        res.explanation = f"Low risk score ({final_score}/100). No prominent malicious indicators observed; message matches standard operational delivery patterns."

    return res
