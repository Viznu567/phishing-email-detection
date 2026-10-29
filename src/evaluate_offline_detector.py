
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
DETECTOR = PROJECT_DIR / "src" / "phishing_detector.py"
SAMPLE = PROJECT_DIR / "samples" / "sample-phishing.eml"
REPORT = PROJECT_DIR / "reports" / "offline-detection-evaluation.md"


def run_detector(email_path):
    return subprocess.run(
        [sys.executable, str(DETECTOR), "--file", str(email_path)],
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True,
        check=False,
    )


def main():
    tests = []

    # Test 1: Existing synthetic phishing sample.
    suspicious = run_detector(SAMPLE)
    suspicious_passed = (
        suspicious.returncode == 0
        and "[HIGH]" in suspicious.stdout
        and "Reply-To domain differs" in suspicious.stdout
        and "SPF authentication failed" in suspicious.stdout
    )
    tests.append((
        "Synthetic phishing sample",
        suspicious_passed,
        "Expected high risk and key warning signals detected."
        if suspicious_passed
        else f"Unexpected result: {suspicious.stderr or suspicious.stdout}",
    ))

    # Test 2: Synthetic benign email.
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
        benign_path = Path(temp_dir) / "benign.eml"
        benign_path.write_text(benign_email, encoding="utf-8")
        benign = run_detector(benign_path)

    benign_passed = (
        benign.returncode == 0
        and "Score: 0" in benign.stdout
        and "No configured warning signals found." in benign.stdout
    )
    tests.append((
        "Synthetic benign email",
        benign_passed,
        "Expected zero score and no configured warning signals."
        if benign_passed
        else f"Unexpected result: {benign.stderr or benign.stdout}",
    ))

    passed_count = sum(passed for _, passed, _ in tests)
    REPORT.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# Offline Phishing Detector Evaluation",
        "",
        f"Generated (UTC): {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Results",
        "",
        "| Test | Result | Details |",
        "|---|---|---|",
    ]

    for name, passed, details in tests:
        safe_details = details.replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| {name} | {'PASS' if passed else 'FAIL'} | {safe_details} |"
        )

    lines.extend([
        "",
        "## Summary",
        "",
        f"- Tests passed: {passed_count}/{len(tests)}",
        f"- Tests failed: {len(tests) - passed_count}",
        "",
        "## Limitations",
        "",
        "- These are controlled synthetic examples, not a representative dataset.",
        "- Passing tests verifies configured behavior, not real-world accuracy.",
        "- A low score does not prove that an email is safe.",
        "- No email links are opened by this evaluation.",
        "",
    ])

    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print(f"Evaluation complete: {passed_count}/{len(tests)} tests passed.")
    print(f"Report saved to: {REPORT}")

    if passed_count != len(tests):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
