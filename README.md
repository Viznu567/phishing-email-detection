# Phishing Email Analysis and Incident Report

## Overview

A cybersecurity training project demonstrating phishing email triage, email-header inspection, IOC extraction, threat-intelligence lookups, and incident report preparation. It also includes an offline detector for analyzing saved `.eml` messages or watching a local demo folder for new messages.

## Run the local detector

Requires Python 3.10 or newer. It uses only the Python standard library; no extra application or package installation is required. Open this folder in VS Code and run these commands in its terminal:

```powershell
python src/phishing_detector.py --file samples/sample-phishing.eml
```

To monitor a local folder for incoming `.eml` files, run:

```powershell
python src/phishing_detector.py --watch demo-inbox --output reports/demo-results.jsonl
```

Copy a saved `.eml` file into `demo-inbox` to see its analysis. Stop with Ctrl+C. Results are appended to the JSON Lines report. The detector checks sender and Reply-To domain mismatches, authentication failures recorded in message headers, pressure wording, links, and punycode hostnames. It does not open links, query reputation services, or connect to Outlook/Gmail. Its risk score is a triage hint, not a verdict.

## Tools

- Email header inspection
- VirusTotal
- URLScan.io
- VS Code terminal / Windows PowerShell
- Python standard library
- CSV and Markdown

## Investigation Activities

- Examined sender and Reply-To fields.
- Reviewed illustrative SPF, DKIM, and DMARC results.
- Extracted email and URL indicators.
- Practised threat-intelligence lookups.
- Documented findings, uncertainty, and recommended remediation.

## Project Structure

- `samples/` — Training email
- `screenshots/` — Tool evidence
- `reports/` — Analysis and incident reports
- `iocs/` — Extracted indicators
- `src/phishing_detector.py` — Offline `.eml` analyzer and local folder watcher
- `demo-inbox/` — Created automatically when folder watching starts

## Safety and Limitations

The initial email is fictional and uses reserved training domains. The example.com scans demonstrate tool usage only. No real malicious activity was confirmed. The local folder watcher is not connected to a live mail service. Real mailbox integration requires selecting a provider and configuring its authorized access method; offline scores should not automatically block, quarantine, or delete messages.

## Skills Demonstrated

- Phishing email triage
- Email header analysis
- IOC extraction
- Threat-intelligence research
- Incident documentation
- Security awareness and remediation

## Disclaimer

This project is intended for cybersecurity education and defensive analysis.
