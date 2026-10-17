import json
from pathlib import Path

import pandas as pd
import streamlit as st


# Project paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ALERTS_FILE = PROJECT_ROOT / "logs" / "alerts.jsonl"

st.set_page_config(
    page_title="Phishing Email Security Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Phishing Email Security Dashboard")
st.caption("Email risk monitoring and security alerts")


def load_alerts():
    """Load recorded email alerts from the JSON Lines log."""
    records = []

    if not ALERTS_FILE.exists():
        return records, "No alert log found yet."

    try:
        with ALERTS_FILE.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                if not line.strip():
                    continue

                try:
                    record = json.loads(line)
                    if isinstance(record, dict):
                        records.append(record)
                except json.JSONDecodeError:
                    st.warning(
                        f"Skipped an invalid log entry at line {line_number}."
                    )

        return records, None

    except OSError as error:
        return [], f"Could not read the alert log: {error}"


def get_risk(record):
    """Get a risk label, using the score if no label is recorded."""
    label = record.get("risk_level") or record.get("risk")

    if label:
        return str(label).replace("_", " ").title()

    try:
        score = int(record.get("score", 0))
    except (TypeError, ValueError):
        score = 0

    if score >= 4:
        return "Higher Risk"
    if score >= 2:
        return "Review"
    return "Low Score"


def get_virustotal_status(record):
    """Summarize the VirusTotal result when available."""
    result = record.get("virustotal", {})

    if not isinstance(result, dict):
        return str(result) if result else "Not available"

    status = result.get("status", "")
    malicious = result.get("malicious")
    suspicious = result.get("suspicious")

    if malicious is not None or suspicious is not None:
        return (
            f"Malicious: {malicious if malicious is not None else 'N/A'}; "
            f"Suspicious: {suspicious if suspicious is not None else 'N/A'}"
        )

    return str(status or "Not available")


alerts, error_message = load_alerts()

if error_message:
    st.info(error_message)

# Refresh the page to load the latest logged alerts.
if st.button("🔄 Refresh dashboard"):
    st.rerun()

if not alerts:
    st.info(
        "No email alerts have been recorded yet. "
        "Start your Gmail monitor and check back after an email is processed."
    )
    st.stop()

# Prepare records for the dashboard.
rows = []

for alert in alerts:
    try:
        score = int(alert.get("score", 0))
    except (TypeError, ValueError):
        score = 0

    attachments = alert.get("attachments", [])
    findings = alert.get("findings", [])

    if not isinstance(attachments, list):
        attachments = [str(attachments)]

    if not isinstance(findings, list):
        findings = [str(findings)]

    rows.append(
        {
            "Time": alert.get("timestamp", alert.get("time", "Unknown")),
            "Sender": alert.get("sender", "Unknown"),
            "Subject": alert.get("subject", "No subject"),
            "Risk": get_risk(alert),
            "Score": score,
            "Attachments": ", ".join(map(str, attachments)) or "None listed",
            "Findings": findings,
            "VirusTotal": get_virustotal_status(alert),
            "Original": alert,
        }
    )

# Summary cards
total_alerts = len(rows)
review_count = sum(row["Score"] >= 2 for row in rows)
higher_risk_count = sum(row["Score"] >= 4 for row in rows)

col1, col2, col3 = st.columns(3)

col1.metric("Emails Recorded", total_alerts)
col2.metric("Emails Requiring Review", review_count)
col3.metric("Higher-Risk Scores", higher_risk_count)

st.divider()

# Search and filter controls
st.subheader("📨 Email Records")

search = st.text_input(
    "Search sender or subject",
    placeholder="Enter an email address or subject",
)

risk_options = ["All"] + sorted({row["Risk"] for row in rows})
selected_risk = st.selectbox("Filter by risk label", risk_options)

filtered_rows = []

for row in rows:
    searchable_text = f"{row['Sender']} {row['Subject']}".lower()

    if search.lower() not in searchable_text:
        continue

    if selected_risk != "All" and row["Risk"] != selected_risk:
        continue

    filtered_rows.append(row)

display_rows = [
    {
        "Time": row["Time"],
        "Sender": row["Sender"],
        "Subject": row["Subject"],
        "Risk": row["Risk"],
        "Score": row["Score"],
        "Attachments": row["Attachments"],
        "VirusTotal": row["VirusTotal"],
    }
    for row in filtered_rows
]

st.dataframe(
    pd.DataFrame(display_rows),
    use_container_width=True,
    hide_index=True,
)

# Detailed investigation view
st.subheader("🔎 Email Investigation")

if filtered_rows:
    choices = [
        f"{index + 1}. {row['Subject']} — {row['Sender']}"
        for index, row in enumerate(filtered_rows)
    ]

    selected_index = st.selectbox(
        "Select an email to inspect",
        range(len(choices)),
        format_func=lambda index: choices[index],
    )

    selected = filtered_rows[selected_index]

    st.write(f"**Sender:** {selected['Sender']}")
    st.write(f"**Subject:** {selected['Subject']}")
    st.write(f"**Risk label:** {selected['Risk']}")
    st.write(f"**Risk score:** {selected['Score']}")
    st.write(f"**Attachments:** {selected['Attachments']}")
    st.write(f"**VirusTotal:** {selected['VirusTotal']}")

    st.write("**Detection findings:**")

    if selected["Findings"]:
        for finding in selected["Findings"]:
            st.write(f"- {finding}")
    else:
        st.write("No detection findings were recorded.")

    with st.expander("View complete recorded alert"):
        st.json(selected["Original"])
else:
    st.info("No emails match your current search and filter.")

st.caption(
    "A low score does not prove an email is safe. "
    "This dashboard displays recorded findings and does not scan attachments."
)