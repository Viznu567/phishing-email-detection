
## Installation

### Requirements
- Python 3.13 or a compatible Python version
- A Google account with Gmail API access
- A VirusTotal API key (optional)

### 1. Clone the repository

```bash
git clone https://github.com/Viznu567/phishing-email-detection.git
cd phishing-email-detection
```

### 2. Create a virtual environment

Windows:

```cmd
py -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
```

### 3. Configure Gmail API access

Enable the Gmail API in Google Cloud Console and configure OAuth credentials for a desktop application.

Place your downloaded OAuth client file in the project root as `credentials.json`. Authorize the application when prompted. The program may create `token.json` locally.

Use only an account you are authorized to monitor.

### 4. Configure VirusTotal (optional)

Create a local `.env` file in the project root and add your VirusTotal API key using the environment variable name expected by the application code.

Never publish your API key, `credentials.json`, or `token.json`.

## Running the Project

### Start Gmail monitoring

```cmd
python src\gmail_monitor.py
```

The monitor checks the Gmail inbox periodically, analyzes available email indicators, records alerts, and may display desktop notifications.

### Start the dashboard

Open a second terminal, activate the virtual environment, and run:

```cmd
python -m streamlit run src\dashboard.py
```

Open the local URL displayed in the terminal, normally `http://localhost:8501`.

Alternatively, on Windows, double-click `start_phishing_project.bat` in the project root to start both programs.

## Features

- Gmail inbox monitoring using OAuth authorization
- Rule-based phishing risk scoring
- Email header, URL, and attachment-filename checks
- Optional VirusTotal domain reputation lookups
- Desktop alerts and JSON Lines logging
- Streamlit dashboard with automatic refresh, charts, filters, and CSV export
- Markdown monitoring and evaluation reports

## Limitations

This is an educational security-monitoring prototype, not a guaranteed phishing blocker. It does not quarantine emails, and filename checks do not scan attachment contents. Detection may miss phishing messages or flag legitimate ones. VirusTotal results are reputation signals, not proof that a message is malicious or safe.

Keep API keys, OAuth credentials, tokens, private email content, and monitoring logs out of public repositories.
