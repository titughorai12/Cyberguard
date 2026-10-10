from app.ml.qr_classifier import classify_qr_content


def analyze_qr_content(content: str) -> dict:
    """Analyze decoded QR content."""

    if not isinstance(content, str) or not content.strip():
        return {
            "success": False,
            "message": "Please provide QR code content.",
        }

    result = classify_qr_content(content)

    if not result.get("success"):
        return result

    return {
        "success": True,
        "message": "QR code content analyzed successfully.",
        "data": result["data"],
    }
