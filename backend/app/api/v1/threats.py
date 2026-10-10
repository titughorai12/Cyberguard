import logging
import json

from fastapi import APIRouter, HTTPException
from sqlalchemy import select

from app.database.connection import SessionLocal
from app.models.security_event import SecurityEvent
from app.models.threat_analysis import ThreatAnalysis
from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/threats")
def get_threats():
    """Return recent URL analyses and normalized security events."""

    if settings.PUBLIC_DEMO_MODE:
        return {
            "success": True,
            "message": "Shared public mode does not expose visitors' scan history.",
            "data": [],
            "count": 0,
            "persisted": False,
        }

    db = SessionLocal()

    try:
        statement = (
            select(ThreatAnalysis)
            .order_by(ThreatAnalysis.created_at.desc())
            .limit(50)
        )

        records = db.execute(statement).scalars().all()

        data = []

        for record in records:
            data.append(
                {
                    "id": record.id,
                    "url": record.url,
                    "domain": record.domain,
                    "threat_type": record.threat_type,
                    "risk_score": record.risk_score,
                    "severity": record.severity,
                    "confidence": record.confidence,
                    "explanation": record.explanation,
                    "recommended_action": record.recommended_action,
                    "evidence": json.loads(record.evidence_json or "[]"),
                    "analysis_type": record.analysis_type,
                    "ai_provider": record.ai_provider,
                    "created_at": (
                        record.created_at.isoformat()
                        if record.created_at
                        else None
                    ),
                }
            )

        event_statement = (
            select(SecurityEvent)
            .order_by(SecurityEvent.created_at.desc())
            .limit(50)
        )
        events = db.execute(event_statement).scalars().all()
        combined = data + [
            {
                "id": f"event-{event.id}",
                "url": event.subject,
                "domain": None,
                "threat_type": event.event_type,
                "risk_score": event.risk_score,
                "severity": event.severity,
                "confidence": event.confidence,
                "explanation": event.explanation,
                "evidence": json.loads(event.evidence_json or "[]"),
                "recommended_action": event.recommended_action,
                "status": event.status,
                "source": event.source,
                "ai_provider": event.ai_provider,
                "analysis_type": event.analysis_type,
                "created_at": (
                    event.created_at.isoformat()
                    if event.created_at
                    else None
                ),
            }
            for event in events
        ]
        combined.sort(key=lambda item: item.get("created_at") or "", reverse=True)
        combined = combined[:50]

        return {
            "success": True,
            "message": "Threat records fetched successfully.",
            "data": combined,
            "count": len(combined),
        }

    except Exception:
        logger.exception("Failed to fetch threat records.")

        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while fetching threats.",
        )

    finally:
        db.close()
