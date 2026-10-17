import os
import requests
from dotenv import load_dotenv
import ctypes
import base64
import ipaddress
import json
import re
import time
from datetime import datetime, timezone
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlparse

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build


# Read-only Gmail permission
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

PROJECT_DIR = Path(__file__).resolve().parent.parent
CREDENTIALS_FILE = PROJECT_DIR / "credentials.json"
TOKEN_FILE = PROJECT_DIR / "token.json"
LOG_DIR = PROJECT_DIR / "logs"
STATE_FILE = LOG_DIR / "processed_ids.json"
ALERT_FILE = LOG_DIR / "alerts.jsonl"
load_dotenv(PROJECT_DIR / ".env", override=True)

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
VT_CACHE = {}
LAST_VT_REQUEST = 0.0

POLL_SECONDS = 60
MAX_MESSAGES = 50

SUSPICIOUS_PHRASES = {
    "verify your account": 2,
    "urgent action required": 2,
    "account suspended": 2,
    "claim your refund": 2,
    "confirm your password": 2,
    "payment failed": 2,
    "click here immediately": 2,
    "unusual sign-in activity": 2,
    "update your payment details": 2,
    "reset your password": 2,
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly",
    "rebrand.ly", "is.gd", "ow.ly"
}

URL_PATTERN = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)

DANGEROUS_ATTACHMENT_EXTENSIONS = {
    ".exe", ".scr", ".com", ".pif",
    ".bat", ".cmd", ".ps1", ".vbs",
    ".vbe", ".js", ".jse", ".hta",
    ".msi", ".lnk", ".reg", ".iso", ".img",
}
def evaluate_attachment_names(attachment_names):
    """Flag attachments with dangerous or disguised file extensions."""
    score = 0
    findings = []

    for filename in attachment_names:
        suffixes = [
            suffix.lower()
            for suffix in Path(filename).suffixes
        ]

        matched_extensions = sorted(
            set(suffixes) & DANGEROUS_ATTACHMENT_EXTENSIONS
        )

        if matched_extensions:
            score += 3
            extensions = ", ".join(matched_extensions)
            findings.append(
                f"Potentially dangerous attachment: {filename} "
                f"(extension: {extensions})"
            )

    return score, findings



def connect_gmail():
    if not CREDENTIALS_FILE.is_file():
        raise FileNotFoundError(
            f"Missing OAuth file: {CREDENTIALS_FILE}"
        )

    creds = None

    if TOKEN_FILE.is_file():
        creds = Credentials.from_authorized_user_file(
            str(TOKEN_FILE), SCOPES
        )

    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())

    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file(
            str(CREDENTIALS_FILE), SCOPES
        )
        creds = flow.run_local_server(port=0)

    TOKEN_FILE.write_text(creds.to_json(), encoding="utf-8")
    return build("gmail", "v1", credentials=creds)


def load_processed_ids():
    if not STATE_FILE.is_file():
        return None

    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else None
    except (json.JSONDecodeError, OSError):
        return None


def save_processed_ids(ids):
    # Preserve the latest message IDs while limiting state-file size.
    STATE_FILE.write_text(
        json.dumps(ids[-5000:], indent=2),
        encoding="utf-8"
    )


def list_inbox_messages(service):
    result = (
        service.users()
        .messages()
        .list(
            userId="me",
            labelIds=["INBOX"],
            maxResults=MAX_MESSAGES
        )
        .execute()
    )
    return result.get("messages", [])


def decode_part(data):
    if not data:
        return ""

    try:
        padding = "=" * (-len(data) % 4)
        raw = base64.urlsafe_b64decode(data + padding)
        return raw.decode("utf-8", errors="replace")
    except (ValueError, TypeError):
        return ""


def extract_text(payload):
    parts_found = []

    def walk(part):
        # Do not analyze attached files as email body text.
        if part.get("filename"):
            return

        mime_type = part.get("mimeType", "")
        body = part.get("body", {})

        if mime_type in ("text/plain", "text/html"):
            text = decode_part(body.get("data", ""))
            if text:
                parts_found.append(text)

        for child in part.get("parts", []):
            walk(child)

    walk(payload)
    return "\n".join(parts_found)


def defang_url(url):
    return (
        url.replace("https://", "hxxps://")
        .replace("http://", "hxxp://")
        .replace(".", "[.]")
    )

def desktop_alert(sender, subject, risk, score, findings, vt_result):
    findings_text = "\n".join(
        f"- {item}" for item in findings[:4]
    )

    if not findings_text:
        findings_text = "- No specific findings recorded."

    if len(findings) > 4:
        findings_text += f"\n- And {len(findings) - 4} more finding(s)"

    vt_status = vt_result.get("status", "unknown")

    if vt_status == "report_found":
        vt_summary = (
            f"Malicious: {vt_result.get('malicious', 0)} | "
            f"Suspicious: {vt_result.get('suspicious', 0)} | "
            f"Harmless: {vt_result.get('harmless', 0)}"
        )
    else:
        vt_summary = f"Lookup status: {vt_status}"

    message = (
        f"RISK: {risk}\n"
        f"Score: {score}\n\n"
        f"From: {sender}\n"
        f"Subject: {subject}\n\n"
        f"DETECTION FINDINGS:\n{findings_text}\n\n"
        f"VIRUSTOTAL:\n{vt_summary}\n\n"
        "Review the original email carefully. "
        "This alert does not prove the message is malicious."
    )

    ctypes.windll.user32.MessageBoxW(
        0,
        message[:3000],
        "Phishing Email Detector",
        0x30
    )


def desktop_alert(sender, subject, risk, score, findings, vt_result):
    message = (
        "Suspicious email indicators detected!\n\n"
        f"From: {sender}\n"
        f"Subject: {subject}\n"
        f"Risk: {risk}\n"
        f"Score: {score}\n\n"
        "Please review this email carefully."
    )

    ctypes.windll.user32.MessageBoxW(
        0,
        message,
        "Phishing Email Detector",
        0x30
    )
    
def virustotal_domain_lookup(domain):
    global LAST_VT_REQUEST

    domain = domain.strip().lower().rstrip(".")

    if not VT_API_KEY:
        return {"status": "disabled"}

    # Skip local and reserved testing domains.
    if (
        domain in {"example.com", "example.org", "example.net"}
        or domain.endswith(
            (".test", ".example", ".invalid", ".localhost")
        )
    ):
        return {"status": "skipped_training_domain"}

    try:
        ipaddress.ip_address(domain)
        return {"status": "skipped_ip_address"}
    except ValueError:
        pass

    if domain in VT_CACHE:
        return VT_CACHE[domain]

    # Keep requests below the public API rate limit.
    wait = 16 - (time.monotonic() - LAST_VT_REQUEST)
    if LAST_VT_REQUEST and wait > 0:
        time.sleep(wait)

    LAST_VT_REQUEST = time.monotonic()

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VT_API_KEY},
            timeout=15,
        )

        if response.status_code == 401:
            return {"status": "invalid_api_key"}

        if response.status_code == 403:
            return {"status": "access_forbidden"}

        if response.status_code == 404:
            result = {"status": "no_report_found"}

        elif response.status_code == 429:
            return {"status": "rate_limited"}

        else:
            response.raise_for_status()
            data = response.json().get("data", {})
            stats = data.get("attributes", {}).get(
                "last_analysis_stats", {}
            )

            result = {
                "status": "report_found",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }

        VT_CACHE[domain] = result
        return result

    except (requests.RequestException, ValueError) as error:
        print(f"VirusTotal lookup error for {domain}: {error}")
        return {"status": "lookup_error"}

def inspect_attachments(payload):
    filenames = []

    def walk(part):
        filename = (part.get("filename") or "").strip()

        if filename:
            filenames.append(filename)

        for child in part.get("parts", []):
            walk(child)

    walk(payload)
    return filenames

def analyze_message(service, message_id):
    message = (
        service.users()
    
        .messages()
        .get(
            userId="me",
            id=message_id,
            format="full"
        )
        .execute()
    )
       

    payload = message.get("payload", {})
    headers = {}

    for header in payload.get("headers", []):
        key = header.get("name", "").lower()
        headers.setdefault(key, []).append(header.get("value", ""))

    sender_header = headers.get("from", ["Unknown"])[0]
    subject = headers.get("subject", ["No subject"])[0]
    reply_to_header = headers.get("reply-to", [""])[0]
    authentication = " ".join(headers.get("authentication-results", []))

    _, sender_address = parseaddr(sender_header)
    _, reply_address = parseaddr(reply_to_header)

    body = extract_text(payload)
    combined_text = f"{subject}\n{body}".lower()
    urls = list(dict.fromkeys(URL_PATTERN.findall(body)))

    findings = []
    score = 0
    
    # Inspect attachment names without opening or downloading files.
    attachment_names = inspect_attachments(payload)

    attachment_score, attachment_findings = (
    evaluate_attachment_names(attachment_names)
    )

    score += attachment_score
    findings.extend(attachment_findings)


    # Heuristic wording checks
    for phrase, points in SUSPICIOUS_PHRASES.items():
        if phrase in combined_text:
            score += points
            findings.append(f"Suspicious wording: {phrase}")

    # Reply-To mismatch check
    if "@" in sender_address and "@" in reply_address:
        sender_domain = sender_address.rsplit("@", 1)[1].lower()
        reply_domain = reply_address.rsplit("@", 1)[1].lower()

        if sender_domain != reply_domain:
            score += 2
            findings.append(
                "Reply-To domain differs from the From domain"
            )

    # Authentication-Results checks, if present
    auth_lower = authentication.lower()

    for mechanism in ("spf", "dkim", "dmarc"):
        if re.search(rf"\b{mechanism}\s*=\s*fail\b", auth_lower):
            score += 2
            findings.append(
                f"Authentication-Results reports {mechanism.upper()} failure"
            )

    # URL checks
    for url in urls:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        if not hostname:
            continue

        try:
            ipaddress.ip_address(hostname)
            score += 3
            findings.append("URL uses an IP address instead of a domain")
        except ValueError:
            pass

        if "xn--" in hostname:
            score += 2
            findings.append("URL contains a punycode hostname")

        if hostname in SHORTENERS:
            score += 2
            findings.append(f"URL uses a known shortening service: {hostname}")

    # VirusTotal: check at most one eligible domain per email.
    vt_result = {"status": "no_eligible_domain"}

    for url in urls:
        parsed_url = urlparse(url.rstrip(".,);]"))
        hostname = (parsed_url.hostname or "").lower().rstrip(".")

        if not hostname:
            continue

        if (
            hostname in {"example.com", "example.org", "example.net"}
            or hostname.endswith(
                (".test", ".example", ".invalid", ".localhost")
            )
        ):
            continue

        vt_result = virustotal_domain_lookup(hostname)

        if vt_result.get("status") == "report_found":
            malicious = vt_result.get("malicious", 0)
            suspicious = vt_result.get("suspicious", 0)

            if malicious >= 3:
                score += 2
                findings.append(
                    f"VirusTotal: {malicious} vendors flagged "
                    f"{hostname} as malicious; investigate"
                )
            elif malicious > 0:
                score += 1
                findings.append(
                    f"Low-confidence VirusTotal signal: "
                    f"{malicious} vendor(s) flagged {hostname}; verify"
                )

            if suspicious > 0:
                score += 1
                findings.append(
                    f"VirusTotal: {suspicious} vendors flagged "
                    f"{hostname} as suspicious"
                )

        elif vt_result.get("status") == "invalid_api_key":
            print("VirusTotal API key was rejected.")
        elif vt_result.get("status") == "rate_limited":
            print("VirusTotal rate limit reached.")

        break

    if score >= 4:
        risk = "HIGHER RISK - INVESTIGATE"
    elif score >= 2:
        risk = "REVIEW - SUSPICIOUS INDICATORS"
    else:
        risk = "LOW SCORE - NOT PROOF OF SAFETY"

    result = {
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "message_id": message_id,
        "from": sender_header,
        "subject": subject,
        "score": score,
        "risk": risk,
        "findings": findings,
        "urls_defanged": [defang_url(url) for url in urls],
        "virustotal": vt_result,
        "attachments": attachment_names,
    }

    print("\n" + "=" * 55)
    print("EMAIL TRIAGE RESULT")
    print("From:", sender_header)
    print("Subject:", subject)
    print("Risk:", risk)
    print("Score:", score)

    if findings:
        print("\nFindings:")
        for finding in findings:
            print("  [!]", finding)
    else:
        print("\nNo configured suspicious indicators detected.")

    if urls:
        print("\nURLs (defanged for safety):")
        for url in urls:
            print(" ", defang_url(url))

    
    with ALERT_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(result) + "\n")

    if score >= 2:
        desktop_alert(
    sender_header,
    subject,
    risk,
    score,
    findings,
    vt_result
)



def main():
    LOG_DIR.mkdir(exist_ok=True)

    service = connect_gmail()
    profile = (
        service.users()
        .getProfile(userId="me")
        .execute()
    )

    print("Gmail connection successful.")
    print("Monitoring account:", profile["emailAddress"])
    print("Checking the inbox every", POLL_SECONDS, "seconds.")
    print("Press Ctrl+C to stop.\n")

    stored_ids = load_processed_ids()

    if stored_ids is None:
        current = list_inbox_messages(service)
        processed_order = [item["id"] for item in current]
        save_processed_ids(processed_order)

        print(
            f"Initial baseline created for {len(processed_order)} "
            "existing inbox messages."
        )
        print("Existing messages will not generate alerts on this first run.")
        print("Send a new harmless test email to test detection.")
    else:
        processed_order = stored_ids

        print(
            f"Loaded {len(processed_order)} previously processed "
            "message IDs."
        )

    processed = set(processed_order)

    while True:
        try:
            current = list_inbox_messages(service)

            # Process oldest new message first.
            new_messages = [
                item for item in reversed(current)
                if item["id"] not in processed
            ]

            for item in new_messages:
                message_id = item["id"]

                try:
                    analyze_message(service, message_id)
                except Exception as error:
                    print(
                        f"Could not analyze message {message_id}: {error}"
                    )
                    continue

                processed.add(message_id)
                processed_order.append(message_id)

            save_processed_ids(processed_order)
            print(
                f"\n[{datetime.now().strftime('%H:%M:%S')}] "
                f"Monitoring... new messages processed: {len(new_messages)}"
            )
            time.sleep(POLL_SECONDS)

        except KeyboardInterrupt:
            print("\nMonitoring stopped by user.")
            break
        except Exception as error:
            print(f"Monitoring error: {error}")
            print("Retrying in 60 seconds...")
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
