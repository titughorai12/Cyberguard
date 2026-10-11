from urllib.parse import urlparse


def classify_qr_content(content: str) -> dict:
    """Check decoded QR content for suspicious patterns."""

    if not isinstance(content, str) or not content.strip():
        return {
            "success": False,
            "message": "Please provide QR code content.",
        }

    content = content.strip()
    indicators = []
    threat_types = []
    risk_score = 0

    parsed = urlparse(content)

    # Check whether the QR content is a web address.
    if parsed.scheme.lower() in ("http", "https") and parsed.hostname:
        if parsed.scheme.lower() == "http":
            risk_score += 15
            threat_types.append("unencrypted_http")
            indicators.append(
                "The URL uses HTTP instead of encrypted HTTPS."
            )

        hostname = parsed.hostname.lower()

        if "xn--" in hostname:
            risk_score += 20
            threat_types.append("encoded_domain_label")
            indicators.append(
                "The domain contains encoded international characters."
            )

        if "@" in parsed.netloc:
            risk_score += 20
            threat_types.append("destination_obfuscation")
            indicators.append(
                "The URL contains an @ symbol in its network location."
            )

        if any(
            word in content.lower()
            for word in ("login", "verify", "password", "banking")
        ):
            risk_score += 15
            threat_types.append("credential_bait_words")
            indicators.append(
                "The URL contains words commonly used in login or "
                "verification links."
            )

    elif content.lower().startswith(("javascript:", "data:")):
        risk_score = 70
        threat_types.append("script_or_data_payload")
        indicators.append(
            "The QR content uses a potentially risky data or script scheme."
        )

    else:
        indicators.append(
            "The QR content is not a standard HTTP or HTTPS URL."
        )

    risk_score = min(risk_score, 100)

    if risk_score >= 75:
        severity = "critical"
    elif risk_score >= 50:
        severity = "high"
    elif risk_score >= 25:
        severity = "medium"
    else:
        severity = "low"

    category = (
        "suspicious_qr_destination"
        if risk_score >= 25
        else "qr_content_review"
    )
    explanation = (
        f"{severity.title()} QR-content assessment ({risk_score}/100) "
        "based on the listed URL/content indicators. A QR code's destination "
        "cannot be declared safe from these checks alone."
    )
    action = (
        "Do not open the destination. Verify the link through a trusted channel and report it if unexpected."
        if risk_score >= 50
        else "Review the destination carefully and avoid entering credentials or payment details unless you independently trust the site."
        if risk_score >= 25
        else "No configured warning pattern was found; verify the destination before opening it."
    )

    return {
        "success": True,
        "message": "QR content analysis completed.",
        "data": {
            "content": content,
            "risk_score": risk_score,
            "risk_score_type": "heuristic_index",
            "score_note": "This 0–100 score is a rule-based warning index, not a calibrated probability that the QR destination is malicious.",
            "severity": severity,
            "event_type": category,
            "threat_types": threat_types,
            "explanation": explanation,
            "recommended_action": action,
            "indicators": indicators,
            "analysis_type": "rule_based",
            "disclaimer": (
                "This analysis checks basic content patterns only. "
                "It does not prove whether the QR code is malicious."
            ),
        },
    }
