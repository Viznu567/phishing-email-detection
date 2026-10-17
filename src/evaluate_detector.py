
import json
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = PROJECT_DIR / "logs" / "alerts.jsonl"
REPORT_FILE = PROJECT_DIR / "reports" / "detection-evaluation.md"


def load_logs():
    records = []

    if not LOG_FILE.exists():
        raise FileNotFoundError(f"Log file not found: {LOG_FILE}")

    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    records.append(item)
            except json.JSONDecodeError:
                print(f"Warning: skipped invalid log line {line_number}")

    return records


def latest_matching(records, subject_fragment):
    matches = [
        item for item in records
        if subject_fragment.lower() in
        item.get("subject", "").lower()
    ]
    return matches[-1] if matches else None


def main():
    records = load_logs()

    suspicious = latest_matching(
        records, "Security test: verify your account"
    )
    benign = latest_matching(
        records, "Meeting agenda for tomorrow"
    )
    vt_test = latest_matching(
        records, "VirusTotal integration test 2"
    )

    tests = []

    if suspicious:
        passed = (
            suspicious.get("score", 0) >= 2
            and any(
                "Suspicious wording" in finding
                for finding in suspicious.get("findings", [])
            )
        )
        tests.append((
            "Suspicious-indicator test",
            passed,
            f"Score: {suspicious.get('score')}; "
            f"findings: {suspicious.get('findings', [])}"
        ))
    else:
        tests.append((
            "Suspicious-indicator test",
            False,
            "No matching record found"
        ))

    if benign:
        passed = (
            benign.get("score", -1) == 0
            and not benign.get("findings", [])
        )
        tests.append((
            "Benign email test",
            passed,
            f"Score: {benign.get('score')}; "
            f"findings: {benign.get('findings', [])}"
        ))
    else:
        tests.append((
            "Benign email test",
            False,
            "No matching record found"
        ))

    if vt_test:
        result = vt_test.get("virustotal", {})
        passed = result.get("status") == "report_found"
        tests.append((
            "VirusTotal integration test",
            passed,
            f"Lookup status: {result.get('status', 'not recorded')}"
        ))
    else:
        tests.append((
            "VirusTotal integration test",
            False,
            "No matching record found"
        ))

    passed_count = sum(1 for _, passed, _ in tests if passed)

    lines = [
        "# Phishing Detector Evaluation",
        "",
        f"Generated (UTC): {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Test Results",
        "",
        "| Test | Result | Evidence |",
        "|---|---|---|",
    ]

    for name, passed, evidence in tests:
        status = "PASS" if passed else "FAIL"
        safe_evidence = evidence.replace("|", "\\|")
        lines.append(f"| {name} | {status} | {safe_evidence} |")

    lines.extend([
        "",
        "## Summary",
        "",
        f"- Tests passed: {passed_count}/{len(tests)}",
        f"- Tests failed: {len(tests) - passed_count}",
        "",
        "## Limitations",
        "",
        "- These are controlled lab tests, not a representative phishing dataset.",
        "- The suspicious test checks a configured phrase, not confirmed maliciousness.",
        "- A zero score does not establish that an email is safe.",
        "- Further testing is needed to estimate false-positive and false-negative rates.",
        "",
    ])

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text("\n".join(lines), encoding="utf-8")

    print(f"Evaluation complete: {passed_count}/{len(tests)} tests passed.")
    print(f"Report saved to: {REPORT_FILE}")


if __name__ == "__main__":
    main()
