from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.message_service import analyze_message
from app.services.event_store import save_security_event
from app.services.message_ai_service import analyze_message_hybrid

router = APIRouter()


class MessageAnalysisRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Message text for hybrid phishing and social-engineering assessment",
    )


@router.post("/message")
def analyze_message_endpoint(request: MessageAnalysisRequest):
    """Assess a message using rules and configured Gemini AI."""

    result = analyze_message_hybrid(analyze_message(request.message), request.message)
    if result.get("success"):
        save_security_event(
            result.get("data", {}).get("event_type", "phishing_or_scam"),
            "message",
            f"Message scan · {len(request.message)} characters",
            result,
        )
    return result
