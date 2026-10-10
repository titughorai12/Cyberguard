from fastapi import APIRouter
from typing import Literal

from pydantic import BaseModel, Field

from app.services.phone_service import analyze_phone_number

router = APIRouter()


class PhoneAnalysisRequest(BaseModel):
    phone_number: str = Field(
        ...,
        min_length=1,
        max_length=30,
        description="Phone number to check",
    )
    region: Literal["IN", "US", "GB", "OTHER"] = Field(
        default="IN",
        description="Numbering region used for the format check",
    )


@router.post("/phone")
def analyze_phone_endpoint(request: PhoneAnalysisRequest):
    """Check phone number formatting and simple digit patterns."""

    return analyze_phone_number(request.phone_number, request.region)
