from datetime import datetime, timezone
import logging

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.event_store import save_security_event

logger = logging.getLogger(__name__)
router = APIRouter()


class LoginEvent(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    source_ip: str = Field(default="unknown", max_length=80)
    device: str = Field(default="unknown", max_length=160)
    location: str = Field(default="unknown", max_length=160)
    success: bool = False
    timestamp: str | None = None


class AuthEventRequest(BaseModel):
    events: list[LoginEvent] = Field(min_length=1, max_length=500)
    known_devices: list[str] = Field(default_factory=list)
    known_locations: list[str] = Field(default_factory=list)


@router.post("/auth-events")
def analyze_auth_events(request: AuthEventRequest):
    """Assess a supplied, authorized authentication-log sample."""
    events = request.events
    failed = [event for event in events if not event.success]
    users = {event.username.lower() for event in failed}
    ips = {event.source_ip for event in failed}
    indicators: list[str] = []
    score = 0

    if len(failed) >= 5:
        score += 30
        indicators.append(
            f"{len(failed)} failed sign-in attempts appear in this sample."
        )
    if len(users) >= 3 and len(ips) == 1:
        score += 35
        indicators.append(
            f"One source IP attempted access to {len(users)} different accounts, "
            "consistent with password-spraying behavior."
        )
    elif len(users) == 1 and len(failed) >= 5:
        score += 15
        indicators.append("Repeated failures target the same account, which may indicate credential guessing.")

    known_devices = {value.casefold() for value in request.known_devices}
    known_locations = {value.casefold() for value in request.known_locations}
    successful = [event for event in events if event.success]
    for event in successful:
        if known_devices and event.device.casefold() not in known_devices:
            score += 20
            indicators.append(
                f"Successful sign-in for {event.username} used a device "
                "not in the supplied known-device list."
            )
            break
    for event in successful:
        if known_locations and event.location.casefold() not in known_locations:
            score += 20
            indicators.append(
                f"Successful sign-in for {event.username} came from a location "
                "not in the supplied known-location list."
            )
            break

    # Flag close, conflicting login locations when parseable timestamps exist.
    parsed = []
    for event in successful:
        try:
            parsed_time = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
            if parsed_time.tzinfo is None:
                parsed_time = parsed_time.replace(tzinfo=timezone.utc)
            parsed.append((parsed_time, event))
        except (ValueError, AttributeError):
            continue
    parsed.sort(key=lambda item: item[0])
    for (first_time, first), (second_time, second) in zip(parsed, parsed[1:]):
        minutes = abs((second_time - first_time).total_seconds()) / 60
        if first.location.casefold() != second.location.casefold() and minutes <= 60:
            score += 25
            indicators.append(
                "Successful sign-ins from different locations occurred within "
                "one hour; verify whether the travel is plausible."
            )
            break

    score = min(score, 100)
    severity = (
        "critical" if score >= 80 else
        "high" if score >= 55 else
        "medium" if score >= 25 else "low"
    )
    if not indicators:
        indicators.append("No configured authentication-anomaly patterns were found in this sample.")
    category = (
        "password_spraying"
        if len(users) >= 3 and len(ips) == 1
        else "account_takeover_risk"
        if score >= 25
        else "authentication_activity"
    )
    explanation = (
        f"{severity.title()} authentication risk ({score}/100). "
        "The assessment uses the supplied event sample and known-device/location lists; "
        "it does not query a live identity provider."
    )
    action = (
        "Temporarily block or challenge the source, require MFA, and review affected accounts."
        if score >= 55
        else "Verify the sign-in with the account owner and require additional authentication if unexpected."
        if score >= 25
        else "Continue monitoring; this sample alone does not establish that the activity is safe."
    )
    result = {
        "success": True,
        "message": "Authentication event assessment completed.",
        "data": {
            "event_type": category,
            "risk_score": score,
            "severity": severity,
            "confidence": 70 if indicators else 45,
            "explanation": explanation,
            "evidence": indicators,
            "recommended_action": action,
            "analysis_type": "transparent_rules",
            "simulation": True,
            "disclaimer": (
                "This prototype evaluates only the events supplied by the user; "
                "it is not connected to a live identity provider."
            ),
        },
    }
    save_security_event(
        category,
        "authentication",
        f"{len(events)} login events · {len(users)} affected account(s)",
        result,
    )
    return result
