# Phishing Detector Evaluation

Generated (UTC): 2026-10-16T19:42:08.840553+00:00

## Test Results

| Test | Result | Evidence |
|---|---|---|
| Suspicious-indicator test | PASS | Score: 2; findings: ['Suspicious wording: verify your account'] |
| Benign email test | PASS | Score: 0; findings: [] |
| VirusTotal integration test | PASS | Lookup status: report_found |

## Summary

- Tests passed: 3/3
- Tests failed: 0

## Limitations

- These are controlled lab tests, not a representative phishing dataset.
- The suspicious test checks a configured phrase, not confirmed maliciousness.
- A zero score does not establish that an email is safe.
- Further testing is needed to estimate false-positive and false-negative rates.
