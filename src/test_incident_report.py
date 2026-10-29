
import unittest
from src.incident_report import build_report


class IncidentReportTests(unittest.TestCase):
    def test_report_contains_key_sections_and_evidence(self):
        result = {
            "file": "sample-phishing.eml",
            "subject": "Urgent: Verify Your Account",
            "from": "security@example.test",
            "reply_to": "support@unrelated.test",
            "risk_score": 10,
            "risk_level": "high",
            "findings": [
                {
                    "signal": "Reply-To domain differs",
                    "detail": "Sender and Reply-To domains differ.",
                }
            ],
            "urls": ["http://example.test/login"],
            "note": "Heuristic triage only.",
        }

        report = build_report(result)

        self.assertIn("# Phishing Email Incident Report", report)
        self.assertIn("## Executive Summary", report)
        self.assertIn("## Evidence and Findings", report)
        self.assertIn("## URLs Observed", report)
        self.assertIn("## Recommended Analyst Actions", report)
        self.assertIn("## Limitations", report)
        self.assertIn("Reply-To domain differs", report)
        self.assertIn("http://example.test/login", report)
        self.assertIn("HIGH", report)
        self.assertIn("Heuristic triage only.", report)

    def test_report_handles_email_without_findings_or_urls(self):
        result = {
            "file": "benign.eml",
            "subject": "Meeting agenda",
            "from": "colleague@example.test",
            "reply_to": "",
            "risk_score": 0,
            "risk_level": "low",
            "findings": [],
            "urls": [],
            "note": "Heuristic triage only.",
        }

        report = build_report(result)

        self.assertIn("No configured warning signals were found.", report)
        self.assertIn("No URLs were extracted.", report)


if __name__ == "__main__":
    unittest.main()
