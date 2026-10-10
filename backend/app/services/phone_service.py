import re


def analyze_phone_number(phone_number: str, region: str = "IN") -> dict:
    """Check plausible numbering format; spam reputation is not available."""
    if not isinstance(phone_number, str) or not phone_number.strip():
        return {"success": False, "message": "Please provide a phone number."}

    original_number = phone_number.strip()
    region = (region or "IN").upper()
    if region not in {"IN", "US", "GB", "OTHER"}:
        region = "OTHER"

    cleaned = re.sub(r"[\s().-]", "", original_number)
    if not re.fullmatch(r"\+?[0-9]+", cleaned):
        return {
            "success": True,
            "message": "The number format contains unsupported characters.",
            "data": _result(original_number, region, False, "Use digits, an optional leading +, spaces, parentheses, or hyphens."),
        }

    digits = cleaned.lstrip("+")
    national = digits
    valid = False
    format_note = ""

    if region == "IN":
        if digits.startswith("91") and len(digits) == 12:
            national = digits[2:]
        valid = len(national) == 10 and national[0] in "6789"
        format_note = "Expected a 10-digit Indian mobile number beginning with 6, 7, 8, or 9, optionally prefixed with +91."
    elif region in {"US", "OTHER"}:
        if region == "US" and digits.startswith("1") and len(digits) == 11:
            national = digits[1:]
        if region == "US":
            valid = len(national) == 10 and national[0] in "23456789" and national[3] in "23456789"
            format_note = "Expected a 10-digit North American number with valid-looking area-code and exchange prefixes."
        else:
            valid = 7 <= len(digits) <= 15
            format_note = "Expected an international number with 7 to 15 digits."
    elif region == "GB":
        if digits.startswith("44") and len(digits) in {11, 12}:
            national = "0" + digits[2:]
        valid = len(national) in {10, 11} and national.startswith("0")
        format_note = "Expected a UK national-format number beginning with 0, or a number with the +44 country code."

    indicators = []
    if valid and len(set(national)) == 1:
        indicators.append("The national number repeats a single digit; verify it was entered correctly.")
    if valid and national in {"0123456789", "1234567890", "9876543210"}:
        indicators.append("The national number is a simple digit sequence; verify it was entered correctly.")

    # This score ranks format anomalies for review. It is not a spam probability.
    risk_score = (0 if valid else 25) + (20 * len(indicators))
    risk_score = min(risk_score, 100)
    severity = (
        "critical" if risk_score >= 80 else
        "high" if risk_score >= 60 else
        "medium" if risk_score >= 35 else "low"
    )

    status = "Valid-looking format" if valid else "Invalid or unsupported format"
    spam_note = (
        "No phone-reputation or spam-report database is connected. This prototype cannot determine whether this number is spam or safe."
    )
    return {
        "success": True,
        "message": f"Number format: {status}. Spam status: not checked.",
        "data": {
            "phone_number": original_number,
            "region": region,
            "format_valid": valid,
            "format_status": status,
            "risk_score": risk_score,
            "severity": severity,
            "score_basis": "format_anomaly_review_only",
            "score_note": "This score reflects format anomalies only; it is not a spam probability or caller reputation verdict.",
            "format_note": format_note,
            "spam_status": "unknown",
            "spam_checked": False,
            "spam_note": spam_note,
            "indicators": indicators,
            "recommended_action": (
                "Recheck the digits and country code. Format validation does not confirm that the number is assigned or reachable."
                if not valid
                else "A plausible format is not proof that the number is active or belongs to the claimed person. Verify the caller independently."
            ),
            "analysis_type": "numbering_format_rules",
            "disclaimer": "Format validation cannot verify ownership, assignment, reachability, or spam reputation.",
        },
    }


def _result(number: str, region: str, valid: bool, note: str) -> dict:
    risk_score = 0 if valid else 25
    return {
        "phone_number": number,
        "region": region,
        "format_valid": valid,
        "format_status": "Valid-looking format" if valid else "Invalid or unsupported format",
        "risk_score": risk_score,
        "severity": "low" if risk_score < 35 else "medium",
        "score_basis": "format_anomaly_review_only",
        "score_note": "This score reflects format anomalies only; it is not a spam probability or caller reputation verdict.",
        "format_note": note,
        "spam_status": "unknown",
        "spam_checked": False,
        "spam_note": "No phone-reputation or spam-report database is connected. This prototype cannot determine whether this number is spam or safe.",
        "indicators": [],
        "recommended_action": "Enter a supported phone-number format and verify the caller through a trusted contact channel.",
        "analysis_type": "numbering_format_rules",
        "disclaimer": "Format validation cannot verify ownership, assignment, reachability, or spam reputation.",
    }
