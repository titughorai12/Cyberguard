from fastapi import Header, HTTPException

from app.core.config import settings


def verify_api_key(
    x_api_key: str | None = Header(default=None),
) -> str:
    """Verify the CyberGuard backend API key."""

    if not settings.BACKEND_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="Backend API key is not configured.",
        )

    if x_api_key != settings.BACKEND_API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key.",
        )

    return x_api_key
