from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.qr_service import analyze_qr_content
from app.services.event_store import save_security_event

router = APIRouter()


class QRAnalysisRequest(BaseModel):
    content: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="Text or URL decoded from a QR code",
    )


@router.post("/qr")
def analyze_qr(request: QRAnalysisRequest):
    """Analyze decoded QR code content for suspicious patterns."""

    result = analyze_qr_content(request.content)

    if result.get("success"):
        save_security_event("qr_content", "qr", "QR content scan", result)

    if not result.get("success"):
        return result

    return result
