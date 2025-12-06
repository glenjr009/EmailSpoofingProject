def header_rules(msg):
    score = 0
    reasons = []

    from_field = msg.get("From", "")
    return_path = msg.get("Return-Path", "")

    # Rule 1: From domain vs Return-Path domain mismatch
    if from_field and return_path:
        from_domain = from_field.split("@")[-1].strip(" >")
        rp_domain = return_path.split("@")[-1].strip(" >")

        if from_domain.lower() != rp_domain.lower():
            score += 2
            reasons.append("From domain and Return-Path domain mismatch")

    # Rule 2: Check authentication results
    auth = msg.get("Authentication-Results", "")
    if auth.strip() == "":
        score += 1
        reasons.append("No SPF/DKIM Authentication-Results header")

    return score, reasons
import re

SUSPICIOUS_KEYWORDS = [
    "verify your account",
    "update your account",
    "password expired",
    "click the link below",
    "confirm your identity",
    "urgent action required",
    "unauthorized login attempt",
    "your account will be closed"
]

def content_rules(body):
    score = 0
    reasons = []
    body_lower = body.lower()

    # Keyword check
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in body_lower:
            score += 2
            reasons.append(f"Suspicious keyword found: '{keyword}'")

    # URL detection
    urls = re.findall(r"https?://[^\s]+", body)
    if len(urls) >= 3:
        score += 1
        reasons.append("Email contains multiple URLs")

    # URL shortener detection
    if any(short in body_lower for short in ["bit.ly", "tinyurl", "goo.gl"]):
        score += 1
        reasons.append("URL shortener detected")

    return score, reasons

THRESHOLD = 3  # You can change based on testing

def analyze_email(msg, body):
    header_score, header_reasons = header_rules(msg)
    content_score, content_reasons = content_rules(body)

    total_score = header_score + content_score
    reasons = header_reasons + content_reasons

    label = "LIKELY SPOOFED / PHISHING" if total_score >= THRESHOLD else "LIKELY LEGITIMATE"

    return {
        "score": total_score,
        "label": label,
        "reasons": reasons,
        "header_score": header_score,
        "content_score": content_score
    }
