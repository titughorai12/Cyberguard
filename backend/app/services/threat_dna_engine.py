import hashlib
from urllib.parse import urlparse

from app.ml.url_classifier import classify_url


def analyze_threat_dna(url: str) -> dict:
    """
    Identify URL characteristics that may indicate a threat.

    This is a rule-based analysis. It does not prove that
    a website is malicious or safe.
    """

    if not isinstance(url, str) or not url.strip():
        return {
            "success": False,
            "message": "Please provide a URL.",
        }

    url = url.strip()

    # Reuse the existing URL classifier.
    result = classify_url(url)

    if not result.get("success"):
        return {
            "success": False,
            "message": result.get(
                "message",
                "Unable to analyze the URL.",
            ),
        }

    # Normalize the URL for analysis.
    normalized_url = url

    if "://" not in normalized_url:
        normalized_url = "https://" + normalized_url

    parsed = urlparse(normalized_url)
    domain = parsed.hostname

    if not domain:
        return {
            "success": False,
            "message": "The URL does not contain a valid domain.",
        }

    domain = domain.lower().rstrip(".")

    # Generate a repeatable fingerprint for this URL.
    fingerprint = hashlib.sha256(
        normalized_url.encode("utf-8")
    ).hexdigest()

    # Extract the indicators reported by the classifier.
    indicators = result.get("evidence", [])

    # Determine a basic risk category.
    risk_score = result.get("rule_risk_score", 0)

    if risk_score >= 75:
        risk_level = "critical"
    elif risk_score >= 50:
        risk_level = "high"
    elif risk_score >= 25:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "success": True,
        "message": "Threat DNA analysis completed.",
        "data": {
            "url": normalized_url,
            "domain": domain,
            "fingerprint": fingerprint,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "indicator_count": len(indicators),
            "indicators": indicators,
            "warnings": result.get("warnings", []),
            "analysis_type": "rule_based",
            "disclaimer": (
                "This analysis identifies URL patterns only. "
                "It does not confirm whether a website is malicious."
            ),
        },
    }