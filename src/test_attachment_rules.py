from gmail_monitor import evaluate_attachment_names

tests = [
    ("meeting-notes.txt", 0),
    ("invoice.exe", 3),
    ("invoice.exe.txt", 3),
    ("report.ps1", 3),
]

failed = 0

for filename, expected_score in tests:
    score, findings = evaluate_attachment_names([filename])
    passed = score == expected_score

    print(
        f"{'PASS' if passed else 'FAIL'} | "
        f"{filename} | score={score} | findings={findings}"
    )

    if not passed:
        failed += 1

print(f"\nResults: {len(tests) - failed}/{len(tests)} tests passed.")

if failed:
    raise SystemExit(1)