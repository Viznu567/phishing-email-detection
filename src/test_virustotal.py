import os
from pathlib import Path

import requests
from dotenv import load_dotenv

# Find the main project folder and load its .env file.
PROJECT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_DIR / ".env", override=True)

API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()


def main():
    print("Starting VirusTotal API test...", flush=True)

    if not API_KEY:
        print("ERROR: API key was not found.")
        print("Check the .env file in the project root.")
        return

    print("API key found. Checking a public test domain...", flush=True)

    try:
        response = requests.get(
            "https://www.virustotal.com/api/v3/domains/google.com",
            headers={"x-apikey": API_KEY},
            timeout=20,
        )

        print("HTTP status:", response.status_code)

        if response.status_code == 200:
            data = response.json().get("data", {})
            stats = data.get("attributes", {}).get(
                "last_analysis_stats", {}
            )

            print("SUCCESS: VirusTotal API is working.")
            print("Domain checked: google.com")
            print("Malicious detections:", stats.get("malicious", 0))
            print("Suspicious detections:", stats.get("suspicious", 0))
            print("Harmless detections:", stats.get("harmless", 0))

        elif response.status_code == 401:
            print("ERROR: API key rejected. Check your VirusTotal key.")
        elif response.status_code == 403:
            print("ERROR: API access forbidden. Check your API permissions.")
        elif response.status_code == 429:
            print("ERROR: API rate limit or quota reached.")
        else:
            print("API request failed. Response:", response.text[:500])

    except requests.RequestException as error:
        print("Network error:", error)


if __name__ == "__main__":
    main()