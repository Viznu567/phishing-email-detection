
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = PROJECT_DIR / "logs" / "alerts.jsonl"
REPORT_FILE = PROJECT_DIR / "reports" / "monitoring-summary.md"


def load_alerts():
    if not LOG_FILE.is_file():
        print(f"No alert log found: {LOG_FILE}")
        return []

    alerts = []

    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    alerts.append(item)
            except json.JSONDecodeError:
                print(f"Warning: Skipping invalid log line {line_number}")

    return alerts


def generate_report():
    alerts = load_alerts()

    if not alerts:
        print("No valid alert records are available yet.")
        return

    risk_counts = Counter(
        item.get("risk", "Unknown") for item in alerts
    )

    finding_counts = Counter(
        finding
        for item in alerts
        for finding in item.get("findings", [])
    )

    vt_counts = Counter(
        item.get("virustotal", {}).get("status", "not_recorded")
        for item in alerts
        if isinstance(item.get("virustotal", {}), dict)
    )

    high_risk = risk_counts.get("HIGHER RISK - INVESTIGATE", 0)
    review = risk_counts.get("REVIEW - SUSPICIOUS INDICATORS", 0)
    low_score = risk_counts.get("LOW SCORE - NOT PROOF OF SAFETY", 0)

    lines = [
        "# Phishing Email Monitoring Summary",
        "",
        f"Generated (UTC): {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Overview",
        "",
        f"- Total analyzed email records: {len(alerts)}",
        f"- Higher-risk classifications: {high_risk}",
        f"- Emails requiring review: {review}",
        f"- Low-score classifications: {low_score}",
        "",
        "> These are rule-based triage results, not confirmed phishing counts. "
        "A low score does not prove an email is safe.",
        "",
        "## VirusTotal Lookup Outcomes",
        "",
    ]

    for status, count in vt_counts.most_common():
        lines.append(f"- {status}: {count}")

    lines.extend(["", "## Most Common Findings", ""])

    if finding_counts:
        for finding, count in finding_counts.most_common(10):
            lines.append(f"- {finding}: {count}")
    else:
        lines.append("- No findings were recorded.")

    lines.extend(["", "## Recent Email Activity", ""])

    for item in reversed(alerts[-10:]):
        lines.extend([
            f"### {item.get('subject', 'No subject')}",
            "",
            f"- Time (UTC): {item.get('time_utc', 'Unknown')}",
            f"- Sender: {item.get('from', 'Unknown')}",
            f"- Risk: {item.get('risk', 'Unknown')}",
            f"- Score: {item.get('score', 0)}",
            f"- VirusTotal status: "
            f"{item.get('virustotal', {}).get('status', 'not_recorded')}",
            "",
        ])

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("Summary report generated successfully.")
    print(f"Analyzed records: {len(alerts)}")
    print(f"Higher-risk classifications: {high_risk}")
    print(f"Emails requiring review: {review}")
    print(f"Report saved to: {REPORT_FILE}")


if __name__ == "__main__":
    generate_report()
