import json
import logging

from app.database.connection import SessionLocal
from app.models.security_event import SecurityEvent
from app.core.config import settings

logger = logging.getLogger(__name__)


def save_security_event(
    event_type: str,
    source: str,
    subject: str,
    result: dict,
) -> None:
    """Persist a normalized detector result for the SOC dashboard."""
    if settings.PUBLIC_DEMO_MODE:
        return
    data = result.get("data", result)
    evidence = data.get("evidence", data.get("indicators", []))
    if not isinstance(evidence, list):
        evidence = [str(evidence)]
    score = data.get("risk_score", 0)
    severity = data.get("severity", "low")
    explanation = data.get("explanation") or (
        f"{event_type.replace('_', ' ').title()} assessment completed using "
        f"{data.get('analysis_type', 'configured detection rules')}."
    )
    action = data.get("recommended_action") or data.get("action") or (
        "Review the evidence. If the activity is unexpected, follow your "
        "organization's incident-response process."
    )
    db = SessionLocal()
    try:
        db.add(
            SecurityEvent(
                event_type=event_type,
                source=source,
                ai_provider=str(data.get("ai_provider", "rules"))[:50],
                analysis_type=str(data.get("analysis_type", "rules_only"))[:80],
                subject=subject[:2000],
                risk_score=float(score or 0),
                severity=str(severity),
                confidence=data.get("confidence"),
                explanation=str(explanation),
                evidence_json=json.dumps(evidence[:30]),
                recommended_action=str(action),
                status=(
                    "open"
                    if str(severity).lower() in {"high", "critical"}
                    else "new"
                ),
            )
        )
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Could not persist security event.")
    finally:
        db.close()
