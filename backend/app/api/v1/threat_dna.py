import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.threat_dna_engine import analyze_threat_dna

logger = logging.getLogger(__name__)

router = APIRouter()


class ThreatDNARequest(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="URL to analyze",
    )


@router.post("/threat-dna")
def analyze_threat_dna_endpoint(request: ThreatDNARequest):
    """Analyze URL characteristics using the Threat DNA engine."""

    try:
        result = analyze_threat_dna(request.url)

        if not result.get("success"):
            raise HTTPException(
                status_code=400,
                detail=result.get(
                    "message",
                    "Threat DNA analysis failed.",
                ),
            )

        return result

    except HTTPException:
        raise

    except Exception:
        logger.exception("Threat DNA analysis failed.")

        raise HTTPException(
            status_code=500,
            detail="An internal error occurred during Threat DNA analysis.",
        )
