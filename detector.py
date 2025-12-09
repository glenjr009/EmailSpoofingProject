import re
import email.utils
from urllib.parse import urlparse

def analyze_email(msg, body, raw_content):
    """
    GRAPH-READY ANALYSIS:
    Splits penalties into Auth, Header, and Content buckets so the UI graphs work.
    """
    # Initialize separate buckets for the graphs
    auth_score = 0
    header_score = 0
    content_score = 0
    reasons = []

    # --- 1. EXTRACT IDENTITIES ---
    from_header = msg.get("From", "")
    return_path = msg.get("Return-Path", "")
    message_id = msg.get("Message-ID", "")
    
    def get_domain(text):
        if not text: return ""
        if "<" in text:
            match = re.search(r"<([^>]+)>", text)
            if match: text = match.group(1)
        if "@" in text:
            return text.split("@")[-1].lower().strip().strip(">")
        return ""

    dom_from = get_domain(from_header)
    dom_return = get_domain(return_path)
    dom_msg_id = get_domain(message_id)

    # --- 2. AUTH / IDENTITY INTEGRITY (Populates "Auth Integrity" Graph) ---
    # Issues here mean the sender is lying about who they are.

    # A. Message-ID Mismatch
    if dom_from and dom_msg_id:
        if dom_from not in dom_msg_id and dom_msg_id not in dom_from:
            common_relays = ["amazonses.com", "google.com", "outlook.com", "protection.outlook.com"]
            if dom_msg_id not in common_relays:
                auth_score += 40
                reasons.append(f"⚠️ Identity Mismatch: Sender '{dom_from}' vs Message-ID '{dom_msg_id}'")

    # B. Return-Path Mismatch
    if dom_from and dom_return:
        if dom_from != dom_return:
             if not dom_return.endswith(dom_from) and not dom_from.endswith(dom_return):
                 auth_score += 30
                 reasons.append(f"⚠️ Return-Path Mismatch: Replies go to '{dom_return}'")

    # --- 3. HEADER ANOMALIES (Populates "Header Anomalies" Graph) ---
    # Issues here mean the email was built with hacking tools or scripts.

    x_mailer = msg.get("X-Mailer", "")
    if "PHP" in x_mailer or "Python" in x_mailer or "PHPMailer" in raw_content:
        header_score += 50
        reasons.append(f"🚫 Scripting Tool Detected: '{x_mailer}'")
    
    if "X-PHP-Originating-Script" in raw_content:
        header_score += 50
        reasons.append("🚫 PHP Script Header Detected")

    # --- 4. CONTENT RISK (Populates "Content Risk" Graph) ---
    
    # Link Analysis
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
    suspicious_link_count = 0
    for url in urls:
        try:
            link_domain = urlparse(url).netloc.lower()
            if dom_from and link_domain and dom_from not in link_domain:
                whitelist = ["facebook.com", "twitter.com", "linkedin.com", "instagram.com", "google.com"]
                if not any(wl in link_domain for wl in whitelist):
                    suspicious_link_count += 1
        except: pass

    if suspicious_link_count > 0:
        content_score += 20
        reasons.append(f"⚠️ External Links Detected: {suspicious_link_count} suspicious links")

    # Keyword Analysis
    keywords = ["urgent", "verify", "suspended", "account locked", "password"]
    if any(k in body.lower() for k in keywords):
        content_score += 15
        reasons.append("⚠️ Suspicious 'Urgency' Keywords found")

    # --- 5. FINAL VERDICT ---
    total_score = auth_score + header_score + content_score

    if total_score == 0:
        label = "LEGITIMATE"
        reasons.append("✅ Structure matches standard protocols")
    elif total_score < 30:
        label = "SUSPICIOUS"
    else:
        label = "LIKELY SPOOF"

    return {
        "score": total_score,
        "auth_score": auth_score,       # Now has real values!
        "header_score": header_score,   # Now has real values!
        "content_score": content_score, # Now has real values!
        "label": label,
        "reasons": reasons
    }