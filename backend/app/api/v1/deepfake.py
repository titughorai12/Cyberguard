import base64
import binascii

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.deepfake_service import analyze_image_visual_content
from app.services.event_store import save_security_event

router = APIRouter()
MAX_IMAGE_BASE64_CHARS = 14_000_000


class MediaValidationRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    file_size: int = Field(gt=0, le=10 * 1024 * 1024)
    mime_type: str = Field(min_length=1, max_length=40)
    image_base64: str = Field(min_length=1, max_length=MAX_IMAGE_BASE64_CHARS)


@router.post("/deepfake")
def validate_media_endpoint(request: MediaValidationRequest):
    """Validate and visually screen an image; never store the uploaded pixels."""
    result = analyze_image_visual_content(
        request.filename,
        request.file_size,
        request.mime_type,
        request.image_base64,
    )
    if result.get("success") and result.get("data", {}).get("visual_ai_screening_performed"):
        save_security_event(
            "possible_deepfake_visual_screen",
            "image",
            f"Image review · {request.filename[:160]}",
            result,
        )
    return result

