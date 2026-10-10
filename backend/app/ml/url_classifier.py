import ipaddress
import re
from urllib.parse import urlparse


# URL endings that may deserve additional scrutiny.
# A TLD alone does not prove a website is malicious.
SUSPICIOUS_TLDS = {
    "click",
    "country",
    "gq",
    "icu",
    "link",
    "ml",
    "monster",
    "online",
    "rest",
    "sbs",
    "shop",
    "tk",
    "top",
    "work",
    "xyz",
}

# Words sometimes found in phishing URLs.
SUSPICIOUS_KEYWORDS = {
    "account",
    "authenticate",
    "banking",
    "confirm",
    "credential",
    "login",
    "password",
    "secure",
    "security",
    "signin",
    "update",
    "verify",
}

# Common URL shorteners.
URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "ow.ly",
    "cutt.ly",
    "shorturl.at",
}


def classify_url(url: str) -> dict:
    """
    Examine URL characteristics using simple detection rules.

    This function does not visit the website or prove
    whether the destination is malicious.
    """

    score = 0
    evidence = []
    warnings = []

    if not isinstance(url, str) or not url.strip():
        return {
            "success": False,
            "message": "Please provide a URL.",
        }

    url = url.strip()

    # Add a scheme when the user provides only a hostname.
    candidate = url

    if "://" not in candidate:
        candidate = "https://" + candidate

    try:
        parsed = urlparse(candidate)

        hostname = parsed.hostname

        if not hostname:
            return {
                "success": False,
                "message": "The URL does not contain a valid hostname.",
            }

        hostname = hostname.lower().rstrip(".")

        # Validate the port, if present.
        try:
            parsed.port
        except ValueError:
            return {
                "success": False,
                "message": "The URL contains an invalid port.",
            }

    except (ValueError, TypeError):
        return {
            "success": False,
            "message": "Unable to parse the supplied URL.",
        }

    # 1. Check the URL scheme.
    if parsed.scheme.lower() not in {"http", "https"}:
        return {
            "success": False,
            "message": "Only HTTP and HTTPS URLs can be analyzed.",
        }

    if parsed.scheme.lower() == "http":
        score += 15
        evidence.append(
            "The URL uses HTTP instead of encrypted HTTPS."
        )

    # 2. Check for an IP address instead of a hostname.
    try:
        ipaddress.ip_address(hostname)

        score += 25
        evidence.append(
            "The URL uses an IP address instead of a domain name."
        )

    except ValueError:
        pass

    # 3. Check the hostname for excessive subdomains.
    hostname_parts = hostname.split(".")

    if len(hostname_parts) >= 5:
        score += 15
        evidence.append(
            "The hostname contains many domain labels."
        )

    # 4. Check for a hostname that imitates a brand using
    # words like login, secure, and account.
    hostname_words = set(
        re.findall(r"[a-z0-9]+", hostname)
    )

    matching_words = hostname_words.intersection(
        SUSPICIOUS_KEYWORDS
    )

    if matching_words:
        score += 15
        evidence.append(
            "The hostname contains authentication-related "
            "keywords: " + ", ".join(sorted(matching_words))
        )

    # 5. Check the top-level domain.
    tld = hostname_parts[-1] if hostname_parts else ""

    if tld in SUSPICIOUS_TLDS:
        score += 15
        evidence.append(
            f"The URL uses the .{tld} top-level domain, "
            "which may warrant additional scrutiny."
        )

    # 6. Check whether the URL contains an @ symbol.
    # In a URL authority section, this can separate user information
    # from the actual hostname.
    if "@" in parsed.netloc:
        score += 20
        evidence.append(
            "The URL contains user-information syntax (@), "
            "which can obscure the destination."
        )

    # 7. Check for a long URL.
    if len(url) > 200:
        score += 10
        evidence.append(
            "The URL is unusually long."
        )

    # 8. Check for URL shortening services.
    if hostname in URL_SHORTENERS:
        score += 15
        evidence.append(
            "The URL uses a shortening service that hides "
            "the final destination."
        )

    # 9. Check for a punycode hostname.
    if "xn--" in hostname:
        score += 20
        evidence.append(
            "The hostname contains an internationalized "
            "domain label that should be checked carefully."
        )

    # Keep the score within the permitted range.
    score = min(score, 100)

    # Assign a severity label.
    if score >= 75:
        severity = "critical"
    elif score >= 50:
        severity = "high"
    elif score >= 25:
        severity = "medium"
    else:
        severity = "low"

    if not evidence:
        warnings.append(
            "No configured suspicious URL patterns were detected. "
            "This does not establish that the website is safe."
        )

    return {
        "success": True,
        "url": url,
        "domain": hostname,
        "rule_risk_score": score,
        "severity": severity,
        "evidence": evidence,
        "warnings": warnings,
        "ai_provider": "rules",
        "message": (
            "URL pattern analysis completed. "
            "This is a heuristic assessment, not a definitive verdict."
        ),
    }