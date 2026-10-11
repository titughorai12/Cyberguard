import logging
import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.core.config import settings
from app.models.threat_analysis import ThreatAnalysis
from app.services.url_service import analyze_url

logger = logging.getLogger(__name__)
router = APIRouter()


class URLAnalysisRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="URL to analyze")


def severity_for(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


@router.post("/analyze")
def analyze_url_endpoint(request: URLAnalysisRequest, db: Session = Depends(get_db)):
    """Analyze a URL, combine optional AI with explainable rules, and persist the finding."""
    result = analyze_url(request.url)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("message", "Unable to analyze URL."))

    rules = result.get("rule_assessment", {})
    ai = result.get("ai_assessment", {})
    rule_score = max(0, min(100, int(rules.get("risk_score") or 0)))
    ai_ready = bool(ai.get("success"))
    if ai_ready:
        ai_score = max(0, min(100, int(ai.get("risk_score") or 0)))
        score = max(rule_score, round(0.65 * ai_score + 0.35 * rule_score))
        threat_type = ai.get("threat_type", "suspicious")
        if threat_type == "likely_safe" and rule_score >= 25:
            threat_type = "suspicious"
        confidence = ai.get("confidence")
        explanation = (
            f"{ai.get('explanation', 'AI assessment completed.')} "
            f"Combined risk score {score}/100 uses the AI assessment ({ai_score}) "
            f"and URL pattern rules ({rule_score})."
        )
        action = ai.get("recommended_action") or "Verify the destination independently before entering sensitive information."
        evidence = list(dict.fromkeys((rules.get("evidence") or []) + (ai.get("evidence") or [])))[:12]
        provider = "gemini+rules"
        analysis_type = "hybrid_rule_ai"
    else:
        score = rule_score
        rule_types = rules.get("threat_types") or []
        if "credential_bait_words" in rule_types:
            threat_type = "possible_phishing"
        elif rule_types:
            threat_type = "suspicious_url_pattern"
        else:
            threat_type = "no_known_url_indicators"
        confidence = None
        evidence = rules.get("evidence") or []
        explanation = (
            f"Rule-based URL pattern analysis produced a score of {score}/100. "
            "The Gemini AI assessment was unavailable; this is not a definitive verdict."
        )
        action = "Verify the website through a trusted channel before entering credentials or payment details."
        provider = "rules"
        analysis_type = "rules_only"

    severity = severity_for(score)
    analysis = None
    if not settings.PUBLIC_DEMO_MODE:
        try:
            analysis = ThreatAnalysis(
                url=result["url"],
                domain=result.get("domain"),
                threat_type=threat_type,
                risk_score=score,
                severity=severity,
                confidence=confidence,
                explanation=explanation,
                recommended_action=action,
                ai_provider=provider,
                evidence_json=json.dumps(evidence[:20]),
                analysis_type=analysis_type,
            )
            db.add(analysis)
            db.commit()
            db.refresh(analysis)
        except Exception:
            db.rollback()
            logger.exception("Failed to save URL analysis.")
            raise HTTPException(status_code=500, detail="Analysis completed, but saving it failed.")

    return {
        "success": True,
        "message": result.get("message"),
        "data": {
            "id": analysis.id if analysis else None,
            "url": result["url"],
            "domain": result.get("domain"),
            "threat_type": threat_type,
            "threat_types": list(dict.fromkeys(
                (rules.get("threat_types") or [])
                + ([ai.get("threat_type")] if ai_ready and ai.get("threat_type") else [])
            )),
            "risk_score": score,
            "risk_score_type": "heuristic_index",
            "score_note": "This is a 0–100 screening index, not a calibrated probability. A live domain-reputation source is not connected.",
            "severity": severity,
            "confidence": confidence,
            "explanation": explanation,
            "evidence": evidence,
            "recommended_action": action,
            "evidence": evidence,
            "ai_provider": provider,
            "analysis_type": analysis_type,
            "created_at": analysis.created_at if analysis else None,
            "rule_assessment": rules,
            "ai_assessment": ai,
            "disclaimer": "This assessment uses URL pattern rules and optional AI. It does not visit the website or query a live reputation feed, and cannot prove that a URL is safe or malicious.",
            "persisted": bool(analysis),
        },
    }

