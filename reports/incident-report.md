# Phishing Email Incident Report

- **Generated (UTC):** 2026-10-29T16:09:18.136501+00:00
- **Analyzed file:** samples\sample-phishing.eml
- **Subject:** Urgent: Verify Your Account
- **From:** Account Security Team <security@example-training.test>
- **Reply-To:** support@unrelated-training.test
- **Risk level:** HIGH
- **Risk score:** 10

## Executive Summary

The rule-based detector classified this email as **HIGH** with a score of **10**. This is a triage result, not confirmation that the email is malicious.

## Evidence and Findings

- **Reply-To domain differs:** From: Account Security Team <security@example-training.test>; Reply-To: support@unrelated-training.test
- **SPF authentication failed:** Authentication-Results reports a failure.
- **DKIM authentication failed:** Authentication-Results reports a failure.
- **DMARC authentication failed:** Authentication-Results reports a failure.
- **Urgent or account-pressure wording:** The subject or body contains common pressure language.
- **Contains clickable URLs:** Found 1 URL(s); destinations were not opened or checked online.

## URLs Observed

- `http://account-verification.example-training.test/login`

## Recommended Analyst Actions

1. Preserve the original email and its headers for investigation.
2. Review the sender, Reply-To address, and authentication results.
3. Investigate listed URLs using approved security tools without opening suspicious links directly.
4. Correlate the findings with mail gateway, endpoint, and identity logs if available.
5. Follow the organization's incident-response process before blocking senders or removing messages.

## Limitations

Heuristic triage only. A low score does not prove safety; no external lookups were performed.

The report does not establish maliciousness. No external lookups are performed by this report generator.
