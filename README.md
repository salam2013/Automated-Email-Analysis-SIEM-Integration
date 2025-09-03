# Automated-Email-Analysis-SIEM-Integration

## Overview

This project demonstrates a **cybersecurity automation pipeline** that monitors and analyzes emails from a Gmail mailbox. Because email remains the **#1 attack vector**, the pipeline provides a proactive defense by:

* **Automatically detecting** suspicious/malicious **links & attachments**
* **Leveraging** **VirusTotal** for threat intelligence
* **Forwarding** structured results to **Splunk SIEM** for monitoring and alerting

---

## Key capabilities

* Gmail IMAP intake (INBOX and Spam) or offline `.eml` scanning
* Robust URL extraction from text/HTML; optional attachment hashing
* VirusTotal v3 URL analysis (submit + poll for verdicts)
* Splunk HEC forwarding with TLS verification or custom CA bundle
* Streamlit UI for one-click scans; CLI for automation
* VS Code launch configs for fast local dev

---

## Architecture & Workflow

1. **Acquire** – Read emails from Gmail (or load `.eml` files)
2. **Parse** – Extract headers, body, URLs, and attachment metadata
3. **Enrich** – Submit URLs to VirusTotal and collect verdict stats
4. **Normalize** – Build a consistent JSON event (subject, indicators, verdicts)
5. **Ship** – Send events to Splunk via HEC (index/sourcetype configurable)
6. **Act** – Search, alert, and visualize in Splunk


<img width="683" height="826" alt="Screenshot 2025-08-24 225349" src="https://github.com/user-attachments/assets/a2500911-844e-4899-a90a-d3f251323924" />




```
Gmail INBOX/Spam → Parser/Extractor → VirusTotal Scan → JSON Event → Splunk HEC → Dashboards & Alerts
```

---

## Quick start

```bash
# 1) Create and activate a virtual environment
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# 2) Install dependencies
pip install -r requirements.txt

# 3) Configure secrets
cp .env.example .env
# Edit .env to add VT_API_KEY and Splunk HEC values. Add EMAIL_* if using IMAP.

# 4a) Run the Streamlit UI
streamlit run app.py

# 4b) Or run the CLI (example: scan 20 newest INBOX emails and push to Splunk)
python src/main.py --limit 20 --mailbox INBOX --push-to-splunk
```

---

## Configuration (.env)

```dotenv
# Gmail IMAP (optional if scanning only .eml files)
EMAIL_USER=your.name@gmail.com
EMAIL_PASS=your-16-char-google-app-password

# VirusTotal
VT_API_KEY=your_virustotal_api_key


<img width="175" height="237" alt="Screenshot 2025-08-26 232118" src="https://github.com/user-attachments/assets/bb0566da-0868-4582-b0c0-fb53b765b80a" />




# Splunk HEC
SPLUNK_URL=https://localhost:8088
SPLUNK_TOKEN=00000000-0000-0000-0000-000000000000
SPLUNK_INDEX=main
SPLUNK_SOURCE=email_automation
SPLUNK_SOURCETYPE=email_automation
SPLUNK_VERIFY_SSL=true
# SPLUNK_CA_CERT=certs/splunk_ca.pem   # use this if Splunk uses a self-signed cert
```


<img width="1887" height="840" alt="Email automation project" src="https://github.com/user-attachments/assets/67297128-cf1e-4d3b-9819-60e523f0bb97" />






---

## Usage

### Streamlit UI

* Launch with `streamlit run app.py`
* Enter Gmail App Password (if using live IMAP) or select `.eml` files
* Check **Push to Splunk** to forward events after scans

### CLI examples

```bash
# Scan latest emails from IMAP
python src/main.py --mailbox INBOX --limit 25 --push-to-splunk

# Scan a folder of .eml files (if supported by your main.py build)
python src/main.py --eml-dir samples --push-to-splunk
```




<img width="1448" height="874" alt="image" src="https://github.com/user-attachments/assets/97b8dba3-7ad4-4bea-a270-b84bd69a8fc3" />






---

## Event model (sent to Splunk)

```json
{
  "timestamp": "2025-08-26T22:25:00Z",
  "message_id": "<...>",
  "from": "Sender <sender@example.com>",
  "to": "Recipient <to@example.com>",
  "subject": "Security alert",
  "links": ["https://example.com/login", "..."],
  "vt_results": [
    {
      "url": "https://example.com/login",
      "result": {"harmless": 68, "malicious": 0, "suspicious": 0},
      "error": null
    }
  ]
}
```

---

## Splunk: getting value fast

Enable HEC (Settings → Data Inputs → **HTTP Event Collector** → New Token), then search:

```spl
index=main sourcetype=email_automation
| stats count by subject

index=main sourcetype=email_automation
| mvexpand vt_results
| eval url=coalesce(mvindex(vt_results.url,0), url)
| eval verdict=case(
  mvindex(vt_results.result.malicious,0)>0, "malicious",
  mvindex(vt_results.result.suspicious,0)>0,"suspicious",
  mvindex(vt_results.result.harmless,0)>0,  "harmless",
  true(),"unknown"
)
| stats count by url verdict
```




<img width="1489" height="756" alt="Screenshot 2025-08-26 233513" src="https://github.com/user-attachments/assets/8fb03e9e-5c67-4fba-a9cf-cd55c5105b56" />






---

## Project structure

```
.
├── app.py                 # Streamlit app
├── src/
│   ├── main.py            # CLI orchestrator
│   ├── email_client.py    # IMAP acquisition
│   ├── parser.py          # URL extraction
│   ├── vt.py              # VirusTotal client
│   └── splunk.py          # Splunk HEC sender
├── samples/               # .eml test messages (optional)
├── docs/                  # screenshots & diagrams
├── .vscode/               # VS Code launch & tasks
├── .env.example
├── requirements.txt
└── README.md
```

---

## Security notes

* Use a **Gmail App Password** (never your primary password)
* Consider masking PII before sending to production Splunk indexes
* Prefer proper CA validation over disabling TLS verification

---

## Development in VS Code

* **Run CLI Scanner** and **Run Streamlit App** launchers included in `.vscode/launch.json`
* Task to **Install requirements** in `.vscode/tasks.json`

---

## Future enhancements

* **Scheduled IMAP polling** with stateful deduplication (message-ID cache)
* **Attachment analysis**: hash & VT lookups; optional detonation via sandbox (Cuckoo/Any.Run)
* **IOC enrichment**: WHOIS, URLhaus, AbuseIPDB, GreyNoise, ASN/geo
* **Alerting hooks**: Slack/Microsoft Teams webhooks; email notifications
* **Policy actions**: optional Gmail/M365 API to quarantine or label suspected phish
* **Dashboard pack**: saved searches + Splunk dashboards as JSON
* **Performance**: async scanning, VT rate-limit backoff, local verdict cache
* **Packaging**: Dockerfile + GitHub Actions CI (lint/test/build), devcontainer
* **Compliance**: configurable redaction/masking of PII before SIEM ingest

---

## Contributing

Issues and PRs are welcome. If you report a parsing issue, include a sanitized `.eml` sample and steps to reproduce.
 spl as SIEM tool
