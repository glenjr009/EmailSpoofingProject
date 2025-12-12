import re
import spf
import dkim
import dns.resolver
import ipaddress
from urllib.parse import urlparse

def extract_sender_ip(msg):
    # Extracts the public IP of the sending server (top-down)
    received = msg.get_all("Received", []) or []
    for h in received:
        ips = re.findall(r'[0-9]{1,3}(?:\.[0-9]{1,3}){3}', h)
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not ip_obj.is_private and not ip_obj.is_loopback:
                    return str(ip_obj)
            except ValueError:
                continue
    return "127.0.0.1"

def check_spf(domain, sender_ip):
    try:
        if not domain:
            return "none", "no domain"
        # Checks if sender_ip is allowed by domain's SPF record
        result = spf.check2(i=sender_ip, s="test@" + domain, h=domain)
        return result[0], result[0]
    except Exception as e:
        return "temperror", str(e)

def check_dkim(raw_bytes):
    try:
        if not isinstance(raw_bytes, (bytes, bytearray)):
            raw_bytes = str(raw_bytes).encode()
        if b"dkim-signature" not in raw_bytes.lower():
            return False, "missing"
        # Verifies the cryptographic signature
        ok = dkim.verify(raw_bytes)
        return bool(ok), ("pass" if ok else "fail")
    except Exception as e:
        return False, f"error:{e}"

def check_dmarc(domain):
    try:
        # Looks up _dmarc.domain TXT record
        answers = dns.resolver.resolve("_dmarc." + (domain or ""), "TXT")
        txts = [r.to_text().strip('"') for r in answers]
        full = " ".join(txts).lower()
        return full, full
    except Exception:
        return None, "none"

def interpret_spf(result):
    mapping = {
        "pass": ("pass", "SPF Passed"),
        "softfail": ("softfail", "SPF SoftFail"),
        "fail": ("fail", "SPF HardFail"),
        "neutral": ("neutral", "SPF Neutral"),
        "none": ("none", "No SPF Record"),
        "permerror": ("permerror", "SPF PermError"),
        "temperror": ("temperror", "SPF TempError")
    }
    return mapping.get(result, ("unknown", f"SPF: {result}"))

def interpret_dkim(ok, reason):
    if ok:
        return ("pass", "DKIM Verified")
    if reason == "missing":
        return ("missing", "DKIM Missing")
    if reason and reason.startswith("error:"):
        return ("error", f"DKIM Error: {reason}")
    return ("fail", "DKIM Failed")

def interpret_dmarc(raw_txt):
    if not raw_txt:
        return ("none", "No DMARC Record")
    txt = raw_txt.lower()
    if "p=reject" in txt:
        return ("reject", "DMARC Policy: Reject")
    if "p=quarantine" in txt:
        return ("quarantine", "DMARC Policy: Quarantine")
    return ("none", "DMARC Policy: None")

def get_domain(address):
    if not address:
        return ""
    if "<" in address:
        m = re.search(r"<([^>]+)>", address)
        if m:
            address = m.group(1)
    if "@" in address:
        return address.split("@")[-1].strip().lower().strip(">")
    return address.strip().lower()

def analyze_email(msg, body, raw_bytes):
    # Safety wrapper to prevent total crash
    try:
        identity_issues = []
        header_issues = []
        content_issues = []
        combined_reasons = []

        auth_score = 0
        header_score = 0
        content_score = 0

        from_header = msg.get("From", "")
        return_path = msg.get("Return-Path", "") or msg.get("Reply-To", "")
        message_id = msg.get("Message-ID", "")

        dom_from = get_domain(from_header)
        dom_return = get_domain(return_path)
        
        # Fallback if return path is missing
        if not dom_return:
            dom_return = dom_from

        sender_ip = extract_sender_ip(msg)

        # --- 1. Authentication Checks ---
        spf_res, spf_reason_raw = check_spf(dom_return, sender_ip)
        spf_code, spf_text = interpret_spf(spf_res)

        dkim_ok, dkim_reason_raw = check_dkim(raw_bytes)
        dkim_code, dkim_text = interpret_dkim(dkim_ok, dkim_reason_raw)

        dmarc_raw, dmarc_reason_raw = check_dmarc(dom_from)
        dmarc_code, dmarc_text = interpret_dmarc(dmarc_raw)

        # --- 2. Alignment Logic ---
        # SPF Align: Return-Path matches From
        spf_aligned = (dom_from in dom_return or dom_return in dom_from)
        spf_pass_final = (spf_code == "pass" and spf_aligned)
        
        # DKIM Pass is generally trusted as aligned in simple checks
        dkim_pass_final = (dkim_code == "pass")

        # DMARC Pass if EITHER passes
        dmarc_status = "pass" if (spf_pass_final or dkim_pass_final) else "fail"

        # --- 3. Scoring ---
        if dmarc_status == "pass":
            auth_score = 0
        else:
            if dmarc_code == "reject":
                auth_score += 100
                combined_reasons.append("DMARC Fail (Reject Policy)")
            elif dmarc_code == "quarantine":
                auth_score += 60
                combined_reasons.append("DMARC Fail (Quarantine Policy)")
            else:
                # If no DMARC policy, penalize individual failures
                if spf_code == "fail":
                    auth_score += 30
                    combined_reasons.append(spf_text)
                elif spf_code == "softfail":
                    auth_score += 10
                    combined_reasons.append(spf_text)
                
                if dkim_code == "fail":
                    auth_score += 20
                    combined_reasons.append(dkim_text)
                elif dkim_code == "missing":
                    auth_score += 10
                    combined_reasons.append(dkim_text)

                if dom_from != dom_return:
                    auth_score += 10
                    combined_reasons.append("Return-Path Mismatch")

        # --- 4. Header Anomalies ---
        x_mailer = msg.get("X-Mailer", "") or ""
        raw_text = raw_bytes.decode(errors="ignore") if isinstance(raw_bytes, (bytes, bytearray)) else str(raw_bytes)
        
        if any(x in x_mailer for x in ["PHPMailer", "PHP", "Python"]) or "phpmailer" in raw_text.lower():
            header_score += 15
            header_issues.append("Scripted Mailer Detected")
            combined_reasons.append("Scripted Mailer Header")

        if "x-php-originating-script" in raw_text.lower():
            header_score += 20
            header_issues.append("PHP Originating Script Header")
            combined_reasons.append("PHP Script Header")

        # --- 5. Content Checks ---
        body_text = body or ""
        body_lower = body_text.lower()

        urls = re.findall(r'http[s]?://\S+', body_text)
        bad_links = 0
        whitelist = ["google.com", "facebook.com", "microsoft.com", "linkedin.com", "twitter.com", "instagram.com"]
        
        for u in urls:
            try:
                dom = urlparse(u).netloc.lower()
                if dom_from and dom_from in dom:
                    continue
                if not any(w in dom for w in whitelist):
                    bad_links += 1
            except:
                continue
                
        if bad_links > 0:
            content_score += 10 + (5 * min(bad_links, 5))
            content_issues.append(f"{bad_links} suspicious links")
            combined_reasons.append("Suspicious external links")

        phishing_terms = ["urgent", "verify", "reset", "confirm", "password", "bank", "login"]
        found = [t for t in phishing_terms if t in body_lower]
        if found:
            content_score += 20 + (5 * min(len(found), 5))
            content_issues.append("Phishing words found")
            combined_reasons.append("Phishing Language")

        attachments = []
        try:
            for part in msg.walk():
                if part.get_filename():
                    attachments.append(part.get_filename())
        except:
            pass
            
        if attachments:
            content_score += 10
            content_issues.append("Attachments present")
            combined_reasons.append("Has Attachments")

        total = auth_score + header_score + content_score

        if total >= 80:
            label = "HIGHLY LIKELY SPOOF"
        elif total >= 50:
            label = "LIKELY SPOOF"
        elif total >= 30:
            label = "SUSPICIOUS"
        else:
            label = "SECURE"

        return {
            "score": total,
            "auth_score": auth_score,
            "header_score": header_score,
            "content_score": content_score,
            "label": label,
            "reasons": combined_reasons,
            "spf_result": spf_code,
            "spf_reason": spf_text,      # <--- RESTORED
            "dkim_result": dkim_code,
            "dkim_reason": dkim_text,    # <--- RESTORED
            "dmarc_result": dmarc_code,
            "dmarc_reason": dmarc_text,  # <--- RESTORED
            "identity_issues": identity_issues,
            "header_issues": header_issues,
            "content_issues": content_issues
        }

    except Exception as e:
        # Fallback to prevent app crash
        return {
            "score": 0,
            "auth_score": 0,
            "header_score": 0,
            "content_score": 0,
            "label": "ERROR",
            "reasons": [f"Analysis failed: {str(e)}"],
            "spf_result": "error",
            "spf_reason": str(e),
            "dkim_result": "error",
            "dkim_reason": "error",
            "dmarc_result": "error",
            "dmarc_reason": "error",
            "identity_issues": [],
            "header_issues": [],
            "content_issues": []
        }