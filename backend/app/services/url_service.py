import logging
from urllib.parse import urlparse

from app.ml.url_classifier import classify_url
from app.services.gemini_service import analyze_threat


logger = logging.getLogger(__name__)


def analyze_url(url: str) -> dict:
    """
    Analyze a URL using rule-based detection and Gemini AI.

    Both assessments are returned separately so that
    their findings remain distinguishable.
    """

    # Validate the supplied URL.
    if not isinstance(url, str) or not url.strip():
        return {
            "success": False,
            "message": "Please provide a URL.",
        }

    url = url.strip()

    # Run the existing rule-based classifier.
    rule_result = classify_url(url)

    if not rule_result.get("success"):
        return rule_result

    # Normalize the URL for the Gemini service.
    candidate_url = url

    if "://" not in candidate_url:
        candidate_url = "https://" + candidate_url

    parsed = urlparse(candidate_url)

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return {
            "success": False,
            "message": "Please provide a valid HTTP or HTTPS URL.",
        }

    # Run the Gemini assessment.
    # The Gemini service handles its own API errors.
    ai_result = analyze_threat(candidate_url)

    # Keep both assessments separate.
    response = {
        "success": True,
        "url": candidate_url,
        "domain": rule_result.get("domain"),
        "rule_assessment": {
            "risk_score": rule_result.get("rule_risk_score"),
            "severity": rule_result.get("severity"),
            "evidence": rule_result.get("evidence", []),
            "warnings": rule_result.get("warnings", []),
        },
        "ai_assessment": ai_result,
    }

    if ai_result.get("success"):
        response["message"] = (
            "URL analysis completed using rule-based detection "
            "and Gemini AI."
        )
    else:
        response["message"] = (
            "Rule-based analysis completed, but Gemini AI "
            "was unavailable."
        )

    return response