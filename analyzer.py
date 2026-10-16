import re
import urllib.parse
from email import message_from_string

class PhishingAnalyzer:
    def __init__(self, raw_email_text):
        self.msg = message_from_string(raw_email_text)
        self.score = 0
        self.indicators = []
        self.extracted_urls = []

    def analyze_headers(self):
        sender = self.msg.get("From", "")
        reply_to = self.msg.get("Reply-To", "")
        subject = self.msg.get("Subject", "")

        # Detect mismatched Reply-To header
        if reply_to and reply_to.lower() not in sender.lower():
            self.score += 25
            self.indicators.append("Mismatched 'Reply-To' header detected.")

        # Detect urgent keywords
        urgent_keywords = ["urgent", "account locked", "verify now", "suspended", "action required", "immediate"]
        if any(kw in subject.lower() for kw in urgent_keywords):
            self.score += 20
            self.indicators.append(f"Urgent/Psychological trigger keyword found in subject: '{subject}'")

    def analyze_body_and_urls(self):
        body = ""
        if self.msg.is_multipart():
            for part in self.msg.walk():
                if part.get_content_type() == "text/plain":
                    body += part.get_payload(decode=True).decode(errors="ignore")
        else:
            payload = self.msg.get_payload(decode=True)
            body = payload.decode(errors="ignore") if payload else (self.msg.get_payload() or "")

        # Extract links
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
        self.extracted_urls = re.findall(url_pattern, body)

        for url in self.extracted_urls:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()

            # Check if domain is a raw IP address
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                self.score += 30
                self.indicators.append(f"Raw IP address used in URL domain: {url}")

            # Check for suspicious top-level domains
            suspicious_tlds = [".xyz", ".top", ".club", ".online", ".site", ".tk", ".ml"]
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                self.score += 15
                self.indicators.append(f"Suspicious TLD detected in domain: {domain}")

            # Check for lookalike/spoofed keywords in domain
            if domain.count(".") > 3 or "verify" in domain or "secure-login" in domain:
                self.score += 20
                self.indicators.append(f"Spoofed or lookalike domain structure: {domain}")

    def get_risk_level(self):
        if self.score >= 50:
            return "HIGH RISK (Phishing Confirmed)"
        elif self.score >= 20:
            return "MEDIUM RISK (Suspicious Email)"
        else:
            return "LOW RISK (Likely Safe)"

    def generate_report(self):
        self.analyze_headers()
        self.analyze_body_and_urls()
        
        return {
            "risk_score": min(self.score, 100),
            "risk_level": self.get_risk_level(),
            "indicators": self.indicators,
            "urls_found": self.extracted_urls
        }

if __name__ == "__main__":
    sample_email = """From: Security Team <support@bank-security-update.com>
Reply-To: attacker-collector@badsite.xyz
Subject: ⚠️ Urgent: Account Suspended - Action Required
Content-Type: text/plain; charset="UTF-8"

Dear User,

We detected unauthorized access to your banking portal.
Please verify your credentials immediately to restore access:

http://192.168.1.50/login/verify-now

Failure to act within 24 hours will permanently disable your account.
"""
    analyzer = PhishingAnalyzer(sample_email)
    res = analyzer.generate_report()

    print("=== PHISHING AWARENESS ANALYSIS REPORT ===")
    print(f"Risk Level  : {res['risk_level']}")
    print(f"Threat Score: {res['risk_score']}/100")
    print("\n[Identified Threat Indicators]")
    for ind in res['indicators']:
        print(f" - {ind}")
    print("\n[Extracted Links]")
    for url in res['urls_found']:
        print(f" - {url}")