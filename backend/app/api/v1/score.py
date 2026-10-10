import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.ml.url_classifier import classify_url

logger = logging.getLogger(__name__)
router = APIRouter()


class ScoreRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="URL to calculate a security risk score for")


@router.post("/score")
def calculate_score(request: ScoreRequest):
    """Calculate an explainable, rule-based URL risk score."""
    try:
        result = classify_url(request.url)
        if not isinstance(result, dict) or not result.get("success"):
            raise HTTPException(status_code=400, detail=result.get("message", "Unable to score this URL."))

        score = max(0, min(100, int(result.get("rule_risk_score") or 0)))
        severity = result.get("severity", "low")
        indicators = result.get("evidence", [])
        if not indicators:
            explanation = "No configured suspicious URL patterns were found. This does not establish that the website is safe."
            action = "Verify the site independently before entering sensitive information."
        else:
            explanation = (
                f"{severity.title()} URL-pattern risk ({score}/100) based on "
                f"{len(indicators)} configured indicator(s). The score is a heuristic, not a verdict."
            )
            action = (
                "Do not enter credentials or payment details. Verify the domain through a trusted channel."
                if score >= 50
                else "Review the listed indicators and verify the destination independently before sharing sensitive information."
            )

        return {
            "success": True,
            "message": "Security score calculated successfully.",
            "data": {
                "url": result.get("url", request.url),
                "domain": result.get("domain"),
                "threat_type": "suspicious" if score >= 25 else "unknown",
                "risk_score": score,
                "severity": severity,
                "confidence": None,
                "explanation": explanation,
                "indicators": indicators,
                "warnings": result.get("warnings", []),
                "recommended_action": action,
                "analysis_type": "transparent_url_rules",
                "disclaimer": "This score uses URL pattern rules only. It does not visit the site or query reputation services and cannot confirm whether the website is malicious.",
            },
        }
    except HTTPException:
        raise
    except Exception:
        logger.exception("Security score calculation failed.")
        raise HTTPException(status_code=500, detail="An internal error occurred while calculating the security score.")

