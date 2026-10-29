
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from phishing_detector import analyze  # noqa: E402


def build_report(result: dict) -> str:
    level = str(result.get("risk_level", "unknown")).upper()
    score = result.get("risk_score", 0)
    findings = result.get("findings", [])
    urls = result.get("urls", [])

    lines = [
        "# Phishing Email Incident Report",
        "",
        f"- **Generated (UTC):** {datetime.now(timezone.utc).isoformat()}",
        f"- **Analyzed file:** {result.get('file', 'Unknown')}",
        f"- **Subject:** {result.get('subject') or '(none)'}",
        f"- **From:** {result.get('from') or '(none)'}",
        f"- **Reply-To:** {result.get('reply_to') or '(none)'}",
        f"- **Risk level:** {level}",
        f"- **Risk score:** {score}",
        "",
        "## Executive Summary",
        "",
        (
            f"The rule-based detector classified this email as **{level}** "
            f"with a score of **{score}**. This is a triage result, "
            "not confirmation that the email is malicious."
        ),
        "",
        "## Evidence and Findings",
        "",
    ]

    if findings:
        for finding in findings:
            signal = finding.get("signal", "Unspecified finding")
            detail = finding.get("detail", "No additional details")
            lines.append(f"- **{signal}:** {detail}")
    else:
        lines.append("- No configured warning signals were found.")

    lines.extend(["", "## URLs Observed", ""])

    if urls:
        for url in urls:
            # Display URLs as code to avoid creating clickable Markdown links.
            lines.append(f"- `{url}`")
    else:
        lines.append("- No URLs were extracted.")

    lines.extend([
        "",
        "## Recommended Analyst Actions",
        "",
        "1. Preserve the original email and its headers for investigation.",
        "2. Review the sender, Reply-To address, and authentication results.",
        "3. Investigate listed URLs using approved security tools without opening "
        "suspicious links directly.",
        "4. Correlate the findings with mail gateway, endpoint, and identity logs "
        "if available.",
        "5. Follow the organization's incident-response process before blocking "
        "senders or removing messages.",
        "",
        "## Limitations",
        "",
        result.get(
            "note",
            "This report is based on configured heuristic checks.",
        ),
        "",
        "The report does not establish maliciousness. No external lookups "
        "are performed by this report generator.",
        "",
    ])

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a Markdown incident report from an .eml file."
    )
    parser.add_argument("--file", required=True, type=Path, help="Email file to analyze")
    parser.add_argument(
        "--output",
        type=Path,
        help="Report destination (default: reports/incident-report.md)",
    )
    args = parser.parse_args()

    try:
        result = analyze(args.file)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    report_path = args.output or PROJECT_DIR / "reports" / "incident-report.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(build_report(result), encoding="utf-8")

    print(f"Incident report saved to: {report_path.resolve()}")
    print(f"Risk level: {result['risk_level'].upper()}")
    print(f"Risk score: {result['risk_score']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
