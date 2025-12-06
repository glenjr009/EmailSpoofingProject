import email

def load_email(path):
    # Open the email file and read it as text
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    # Convert raw text into an email message object
    msg = email.message_from_string(raw)
    return msg

def get_email_body(msg):
    # If email has multiple parts (HTML + Plain text etc.)
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    return payload.decode(errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            return payload.decode(errors="ignore")
    
    return ""  # If no body found

from detector import analyze_email

if __name__ == "__main__":
    msg = load_email("samples/spoof1.eml")
    body = get_email_body(msg)

    result = analyze_email(msg, body)

    print("===== EMAIL SPOOFING DETECTION =====")
    print("Decision:", result["label"])
    print("Total Score:", result["score"])
    print(f"Header Score: {result['header_score']} | Content Score: {result['content_score']}")
    print("\nReasons:")
    for r in result["reasons"]:
        print(" -", r)
