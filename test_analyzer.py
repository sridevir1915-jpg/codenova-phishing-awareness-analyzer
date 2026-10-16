import unittest
from analyzer import PhishingAnalyzer

class TestPhishingAnalyzer(unittest.TestCase):

    def test_safe_email(self):
        email = """From: HR Team <hr@company.com>
Subject: Weekly Newsletter
Content-Type: text/plain

Here is the weekly update. Check http://company.com/news for details."""
        analyzer = PhishingAnalyzer(email)
        report = analyzer.generate_report()
        self.assertEqual(report["risk_level"], "LOW RISK (Likely Safe)")

    def test_phishing_email(self):
        email = """From: Security <security@bank.com>
Reply-To: attacker@evil.xyz
Subject: Urgent: Account Locked
Content-Type: text/plain

Click here: http://192.168.1.1/login"""
        analyzer = PhishingAnalyzer(email)
        report = analyzer.generate_report()
        self.assertEqual(report["risk_level"], "HIGH RISK (Phishing Confirmed)")
        self.assertGreaterEqual(report["risk_score"], 50)

if __name__ == "__main__":
    unittest.main()