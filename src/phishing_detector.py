"""Local, offline phishing triage for .eml files and a watched demo folder."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path
import ipaddress
from urllib.parse import urlsplit


URL_RE = re.compile(r"https?://[^\s<>\]\[\"'()]+", re.IGNORECASE)
SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "buff.ly",
    "ow.ly",
    "cutt.ly",
    "rebrand.ly",
}
URGENCY_RE = re.compile(
    r"\b(urgent|immediately|verify your account|account (?:will be|is) (?:suspended|restricted)|"
    r"act now|password expires|payment overdue)\b",
    re.IGNORECASE,
)


def analyze(path: Path) -> dict:
    """Analyze an RFC 822 email file without contacting its links or sender."""
    message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
    sender = str(message.get("From", ""))
    reply_to = str(message.get("Reply-To", ""))
    subject = str(message.get("Subject", ""))
    auth_results = " ".join(str(v) for v in message.get_all("Authentication-Results", []))
    body_parts: list[str] = []
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body_parts.append(str(part.get_content()))
                except (LookupError, UnicodeError):
                    continue
    else:
        try:
            body_parts.append(str(message.get_content()))
        except (LookupError, UnicodeError):
            pass
    body = "\n".join(body_parts)
    content = f"{subject}\n{body}"
    urls = list(dict.fromkeys(URL_RE.findall(content)))
    findings: list[dict[str, str]] = []
    score = 0

    def flag(points: int, label: str, detail: str) -> None:
        nonlocal score
        score += points
        findings.append({"signal": label, "detail": detail})

    if sender and reply_to:
        sender_domains = {d.lower() for d in re.findall(r"@([A-Za-z0-9.-]+)", sender)}
        reply_domains = {d.lower() for d in re.findall(r"@([A-Za-z0-9.-]+)", reply_to)}
        if sender_domains and reply_domains and sender_domains.isdisjoint(reply_domains):
            flag(2, "Reply-To domain differs", f"From: {sender}; Reply-To: {reply_to}")

    for method in ("spf", "dkim", "dmarc"):
        if re.search(rf"\b{method}\s*=\s*(fail|softfail|temperror|permerror)\b", auth_results, re.I):
            flag(2, f"{method.upper()} authentication failed", "Authentication-Results reports a failure.")

    if URGENCY_RE.search(content):
        flag(1, "Urgent or account-pressure wording", "The subject or body contains common pressure language.")
    if urls:
        flag(1, "Contains clickable URLs", f"Found {len(urls)} URL(s); destinations were not opened or checked online.")
    for url in urls:
        try:
            host = (urlsplit(url).hostname or "").lower().rstrip(".")
        except ValueError:
            host = ""

        if not host:
            continue

        if host.startswith("xn--") or ".xn--" in host:
            flag(
                2,
                "Internationalized domain",
                f"URL uses a punycode hostname: {host}",
            )

        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            flag(
                2,
                "IP-address URL",
                f"URL uses an IP address instead of a domain: {host}",
            )

        if host in SHORTENERS:
            flag(
                2,
                "Known URL shortener",
                f"URL uses a known shortening service: {host}",
            )


    level = "high" if score >= 5 else "medium" if score >= 3 else "low"
    return {
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "file": str(path),
        "subject": subject,
        "from": sender,
        "reply_to": reply_to,
        "risk_score": score,
        "risk_level": level,
        "findings": findings,
        "urls": urls,
        "note": "Heuristic triage only. A low score does not prove safety; no external lookups were performed.",
    }


def show(result: dict) -> None:
    print(f"[{result['risk_level'].upper()}] {result['file']}")
    print(f"  Subject: {result['subject'] or '(none)'}")
    print(f"  From: {result['from'] or '(none)'}")
    print(f"  Score: {result['risk_score']}")
    for finding in result["findings"]:
        print(f"  - {finding['signal']}: {finding['detail']}")
    if not result["findings"]:
        print("  - No configured warning signals found.")
    print(f"  {result['note']}")


def write_jsonl(result: dict, output: Path | None) -> None:
    if output is None:
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(result, ensure_ascii=False) + "\n")


def watch(folder: Path, output: Path | None, interval: float) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    seen: dict[Path, tuple[int, int]] = {}
    print(f"Watching {folder.resolve()} for .eml files (Ctrl+C to stop)")
    try:
        while True:
            for path in sorted(folder.glob("*.eml")):
                try:
                    stat = path.stat()
                    signature = (stat.st_size, stat.st_mtime_ns)
                    if signature == seen.get(path):
                        continue
                    # Skip files that are still being copied into the folder.
                    time.sleep(0.25)
                    after = path.stat()
                    if (after.st_size, after.st_mtime_ns) != signature:
                        continue
                    result = analyze(path)
                    show(result)
                    write_jsonl(result, output)
                    seen[path] = signature
                except (OSError, ValueError) as error:
                    print(f"Could not analyze {path}: {error}", file=sys.stderr)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopped watching.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", type=Path, help="Analyze one .eml file")
    source.add_argument("--watch", type=Path, help="Watch a folder for new .eml files")
    parser.add_argument("--output", type=Path, help="Append results as JSON Lines to this file")
    parser.add_argument("--interval", type=float, default=2.0, help="Folder scan interval in seconds (default: 2)")
    args = parser.parse_args()
    if args.interval <= 0:
        parser.error("--interval must be greater than zero")
    if args.file:
        try:
            result = analyze(args.file)
        except (OSError, ValueError) as error:
            parser.error(str(error))
        show(result)
        write_jsonl(result, args.output)
    else:
        watch(args.watch, args.output, args.interval)


if __name__ == "__main__":
    main()
