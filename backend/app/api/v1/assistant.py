import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.ml.assistant_engine import ask_assistant

logger = logging.getLogger(__name__)

router = APIRouter()


class AssistantRequest(BaseModel):
    question: str = Field(
        ...,
        min_length=1,
        max_length=4000,
        description="Cybersecurity question",
    )


@router.post("/assistant")
def assistant_endpoint(request: AssistantRequest):
    """Ask CyberGuard Assistant a cybersecurity question."""

    try:
        result = ask_assistant(request.question)

        if not result.get("success"):
            raise HTTPException(
                status_code=503,
                detail=result.get(
                    "message",
                    "Assistant request failed.",
                ),
            )

        return result

    except HTTPException:
        raise

    except Exception:
        logger.exception("Assistant API request failed.")

        raise HTTPException(
            status_code=500,
            detail="An internal error occurred in CyberGuard Assistant.",
        )
