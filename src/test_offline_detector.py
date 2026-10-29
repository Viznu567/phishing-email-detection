
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
DETECTOR = PROJECT_DIR / "src" / "phishing_detector.py"
SAMPLE = PROJECT_DIR / "samples" / "sample-phishing.eml"


class OfflineDetectorTests(unittest.TestCase):
    def test_sample_detects_expected_signals(self):
        result = subprocess.run(
            [
                sys.executable,
                str(DETECTOR),
                "--file",
                str(SAMPLE),
            ],
            cwd=PROJECT_DIR,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(
            result.returncode,
            0,
            msg=f"Detector failed:\n{result.stderr}",
        )
        self.assertIn("[HIGH]", result.stdout)
        self.assertIn("Reply-To domain differs", result.stdout)
        self.assertIn("SPF authentication failed", result.stdout)
        self.assertIn("DKIM authentication failed", result.stdout)
        self.assertIn("DMARC authentication failed", result.stdout)
        self.assertIn("Urgent or account-pressure wording", result.stdout)
        self.assertIn("Contains clickable URLs", result.stdout)

    def test_jsonl_output_is_valid(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "alerts.jsonl"

            result = subprocess.run(
                [
                    sys.executable,
                    str(DETECTOR),
                    "--file",
                    str(SAMPLE),
                    "--output",
                    str(output_file),
                ],
                cwd=PROJECT_DIR,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(
                result.returncode,
                0,
                msg=f"Detector failed:\n{result.stderr}",
            )
            self.assertTrue(output_file.exists())

            lines = output_file.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)

            record = json.loads(lines[0])
            self.assertEqual(record["risk_level"], "high")
            self.assertGreaterEqual(record["risk_score"], 5)
            self.assertIsInstance(record["findings"], list)
            self.assertTrue(record["urls"])

    def test_benign_email_has_no_configured_warning_signals(self):
        benign_email = (
            "From: colleague@example.test\n"
            "To: analyst@example.test\n"
            "Subject: Meeting agenda for tomorrow\n"
            "MIME-Version: 1.0\n"
            "Content-Type: text/plain; charset=UTF-8\n"
            "\n"
            "Hello,\n"
            "Here is the agenda for our team meeting tomorrow.\n"
            "Regards,\n"
            "Colleague\n"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            email_file = Path(temp_dir) / "benign.eml"
            email_file.write_text(benign_email, encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(DETECTOR),
                    "--file",
                    str(email_file),
                ],
                cwd=PROJECT_DIR,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(
                result.returncode,
                0,
                msg=f"Detector failed:\n{result.stderr}",
            )
            self.assertIn("Score: 0", result.stdout)
            self.assertIn("No configured warning signals found.", result.stdout)
    def test_ordinary_url_alone_is_not_high_risk(self):
        email = (
            "From: colleague@example.test\n"
            "To: analyst@example.test\n"
            "Subject: Team meeting information\n"
            "Content-Type: text/plain; charset=UTF-8\n"
            "\n"
            "Here is the meeting information: "
            "https://www.example.test/meeting\n"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            email_file = Path(temp_dir) / "ordinary_url.eml"
            email_file.write_text(email, encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(DETECTOR),
                    "--file",
                    str(email_file),
                ],
                cwd=PROJECT_DIR,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(
            result.returncode,
            0,
            msg=f"Detector failed:\n{result.stderr}",
        )
        self.assertNotIn("[HIGH]", result.stdout)
        self.assertIn("Contains clickable URLs", result.stdout)
    def test_ip_address_url_is_flagged(self):
        email = (
            "From: sender@example.test\n"
            "To: analyst@example.test\n"
            "Subject: Review this page\n"
            "Content-Type: text/plain; charset=UTF-8\n"
            "\n"
            "Please review http://192.0.2.10/login\n"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            email_file = Path(temp_dir) / "ip_url.eml"
            email_file.write_text(email, encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(DETECTOR),
                    "--file",
                    str(email_file),
                ],
                cwd=PROJECT_DIR,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(
            result.returncode,
            0,
            msg=f"Detector failed:\n{result.stderr}",
        )
        self.assertIn("IP-address URL", result.stdout)

    def test_known_url_shortener_is_flagged(self):
        email = (
            "From: sender@example.test\n"
            "To: analyst@example.test\n"
            "Subject: Shared resource\n"
            "Content-Type: text/plain; charset=UTF-8\n"
            "\n"
            "Please review https://bit.ly/example-test\n"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            email_file = Path(temp_dir) / "short_url.eml"
            email_file.write_text(email, encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(DETECTOR),
                    "--file",
                    str(email_file),
                ],
                cwd=PROJECT_DIR,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(
            result.returncode,
            0,
            msg=f"Detector failed:\n{result.stderr}",
        )
        self.assertIn("Known URL shortener", result.stdout)




if __name__ == "__main__":
    unittest.main(verbosity=2)
