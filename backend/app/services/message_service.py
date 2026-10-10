import re


SUSPICIOUS_PHRASES = [
    "verify your account",
    "account suspended",
    "account blocked",
    "urgent action required",
    "claim your prize",
    "you have won",
    "send your otp",
    "share your otp",
    "confirm your password",
    "click immediately",
]

SENSITIVE_PHRASES = [
    "password",
    "one time password",
    "one-time password",
    "otp",
    "bank details",
    "credit card",
]

IMPERSONATION_ROLES = [
    "ceo", "chief executive", "principal", "teacher", "professor",
    "government officer", "police", "tax department", "bank support",
    "it support", "human resources", "hr department", "your manager",
]
IMPERSONATION_REQUESTS = [
    "send the otp", "share the otp", "wire transfer", "transfer money",
    "buy gift cards", "send payment", "confirm your password",
    "verify your account", "share your password", "urgent payment",
]

URL_PATTERN = re.compile(
    r"https?://[^\s]+|www\.[^\s]+",
    re.IGNORECASE,
)


def analyze_message(message: str) -> dict:
    """Screen a message for common scam warning signs."""

    if not isinstance(message, str) or not message.strip():
        return {
            "success": False,
            "message": "Please provide a message to analyze.",
        }

    text = message.strip().lower()
    indicators = []
    risk_score = 0
    impersonation_signal = (
        any(role in text for role in IMPERSONATION_ROLES)
        and any(request in text for request in IMPERSONATION_REQUESTS)
    )

    if impersonation_signal:
        indicators.append(
            "The message claims an authority or trusted role while requesting money, credentials, or urgent account action. Verify the sender independently."
        )
        risk_score += 25

    for phrase in SUSPICIOUS_PHRASES:
        if phrase in text:
            indicators.append(
                f"The message contains a suspicious phrase: '{phrase}'."
            )
            risk_score += 15

    if any(phrase in text for phrase in SENSITIVE_PHRASES):
        indicators.append(
            "The message mentions sensitive information or credentials."
        )
        risk_score += 20

    if URL_PATTERN.search(text):
        indicators.append(
            "The message contains a web link. Check its destination "
            "before opening it."
        )
        risk_score += 10

    risk_score = min(risk_score, 100)

    if risk_score >= 75:
        severity = "critical"
    elif risk_score >= 50:
        severity = "high"
    elif risk_score >= 25:
        severity = "medium"
    else:
        severity = "low"

    if not indicators:
        indicators.append(
            "No configured warning patterns were detected."
        )

    severity = (
        "critical" if risk_score >= 75 else
        "high" if risk_score >= 50 else
        "medium" if risk_score >= 25 else "low"
    )
    category = (
        "impersonation"
        if impersonation_signal
        else "phishing"
        if URL_PATTERN.search(text)
        else "social_engineering"
    )
    action = (
        "Do not open the link or share credentials. Report the message and verify the request using an independently known contact channel."
        if risk_score >= 50 else
        "Treat links and requests for sensitive information cautiously; verify the sender through a trusted channel."
        if risk_score >= 25 else
        "No configured warning patterns were found. Verify the sender if the request is unexpected."
    )

    return {
        "success": True,
        "message": "Message screening completed.",
        "data": {
            "risk_score": risk_score,
            "severity": severity,
            "event_type": category,
            "explanation": (
                f"{severity.title()} {category.replace('_', ' ')} assessment "
                f"({risk_score}/100) based on the listed message indicators. "
                "This is a rules-based screen, not proof of fraud."
            ),
            "recommended_action": action,
            "indicators": indicators,
            "analysis_type": "rule_based",
            "disclaimer": (
                "This tool checks configured warning patterns only. "
                "It cannot confirm whether a message is fraudulent."
            ),
        },
    }
