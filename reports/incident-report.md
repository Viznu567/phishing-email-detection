\# Phishing Email Analysis and Incident Report



\## 1. Incident Information

\- Incident ID: PHISH-001

\- Analyst: Vishnu Vardhan

\- Incident Type: Suspected phishing email

\- Sample: sample-real-training.eml

\- Environment: Defensive training lab



\## 2. Executive Summary

An email with the subject "IRAS | Internal Revenue Service/Refund #659010349" was investigated. The email claims to be from a General Tax Authority and refers to a refund bill of 249 SGD. Its content contains a defanged image URL and a defanged hyperlink.



The exact Fanlink URL received 4/92 detections in the VirusTotal report reviewed. URLScan showed no existing scan for the exact URL. These findings justify further investigation but do not conclusively establish that the URL or email is malicious.



\## 3. Email Header Analysis

\- From: accounts@iinet.net.au

\- To: accounts@iinet.net.au

\- Subject: IRAS | Internal Revenue Service/Refund #659010349

\- Date: 17 December 2023, 04:42:11 UTC

\- SPF: Pass, according to the supplied Authentication-Results header

\- DKIM: Not established from the supplied excerpt

\- DMARC: Not established from the supplied excerpt

\- Reported sender IP: 203.59.1.107



\### Header observations

The sender and recipient fields contain the same email address. The email uses tax-refund wording. The SPF pass result does not establish that the message is legitimate.



\## 4. Extracted Indicators



\### Defanged URLs

\- hxxps://i\[.]gyazo\[.]com/513346e2325fbe72b51116e044eb5889\[.]jpg

\- hxxps://fanlink\[.]to/tFR28R



\### Associated domains

\- gyazo.com

\- fanlink.to



\### Other indicator

\- Reported sender IP: 203.59.1.107



These indicators are extracted from the sample. Their inclusion does not automatically establish maliciousness.



\## 5. Threat Intelligence Findings



\### VirusTotal — gyazo.com

\- Detection ratio: 1/92

\- Observation: One security vendor flagged the domain.

\- Assessment: Inconclusive domain-level evidence.



\### VirusTotal — fanlink.to

\- Detection ratio: 2/92

\- Observation: Two security vendors flagged the domain, including a phishing classification.

\- Assessment: Inconclusive domain-level evidence.



\### VirusTotal — exact Fanlink URL

\- Indicator: https://fanlink.to/tFR28R

\- Detection ratio: 4/92

\- Observation: Four security vendors flagged the URL.

\- Assessment: Suspicious; requires corroboration.



\### URLScan — exact Fanlink URL

\- Exact URL scan: Never scanned

\- Existing hostname scans: 3

\- Most recent hostname scan: 8 days ago

\- Hostname verdicts: No malicious verdicts displayed in the captured screenshot.

\- Assessment: The exact URL remains unassessed by URLScan.



\### Limitations

\- Vendor detections may include false positives.

\- Domain reputation does not necessarily describe a specific URL path.

\- No live destination was visited.

\- The sender IP was not independently validated.

\- No final malicious verdict has been confirmed.



\## 6. Final Classification

\- Classification: Suspicious email; further investigation required

\- Severity: Medium for triage purposes

\- Confidence: Moderate that the email warrants investigation

\- Confirmed compromise: Not established



The severity is a preliminary triage assessment, not a confirmed incident-impact rating.



\## 7. Recommended Actions

1\. Preserve the original email and its headers.

2\. Search for the same subject, URLs, and sender details in authorized mail logs.

3\. Check whether any recipients clicked the link or submitted credentials.

4\. Review relevant endpoint and identity logs if user interaction is confirmed.

5\. Block indicators only after validation and according to organizational policy.

6\. Quarantine matching messages if the investigation confirms malicious activity.

7\. Reset credentials and revoke sessions if compromise is established.

8\. Inform affected users and provide targeted phishing-awareness guidance.



\## 8. Evidence Files

\- samples/sample-real-training.eml

\- reports/header-analysis.txt

\- reports/tool-analysis.txt

\- iocs/indicators.csv

\- screenshots/04-virustotal-gyazo.png

\- screenshots/05-virustotal-fanlink.png

\- screenshots/06-urlscan-fanlink-exact-url.png



\## 9. Conclusion

The investigation identified suspicious phishing-style content and a URL with multiple security-vendor detections. The evidence supports continued investigation, but it does not prove that the email caused a compromise or that the destination is definitively malicious.

