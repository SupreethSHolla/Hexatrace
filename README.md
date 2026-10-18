# HEXATRACE

**HEXATRACE** is a cybersecurity log-analysis prototype for an IBM Z datathon. It helps analysts turn structured security events into explainable findings, correlated incident timelines, and investigation reports.

The current project is a local web application that accepts CSV files. It does **not** connect directly to an IBM Z system or collect SMF records itself. For an IBM Z demonstration, export or transform authorized events into the CSV format below, then upload them for analysis.

## What it does

- Analyzes the included `sample_logs.csv` file or an uploaded CSV.
- Applies transparent, rule-based risk scoring to supported event types.
- Highlights patterns such as repeated failed logins, a successful login after repeated failures, suspicious command text, privilege changes, and malware or ransomware alerts.
- Groups suspicious events by source IP and user to build incident timelines.
- Displays explanations, recommendations, evidence gaps, and analyst review status.
- Masks source IP addresses and user names in displayed findings and PDF reports.
- Generates incident PDFs and a full-analysis PDF.
- Builds and verifies a SHA-256 hash chain for analyzed event records.

Risk scores are heuristic investigation priorities, not probabilities or proof of malicious activity. The hash chain is held in application memory; it is not a durable or externally immutable audit log.

## Project files

| File | Purpose |
| --- | --- |
| `app.py` | Flask web application, dashboard, API routes, and PDF report generation |
| `engine.py` | CSV normalization, detection rules, incident correlation, and hash-chain logic |
| `sample_logs.csv` | Sample dataset used by the dashboard's **Analyze Sample Logs** action |
| `Tested Log/hexatrace_dataset.csv` | Additional example dataset |
| `reports/` | Example JSON analysis outputs |

## Requirements

- Python 3
- Flask
- pandas
- ReportLab

## Run locally on Windows

From the project directory, create a virtual environment, install the dependencies, and start the app:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install Flask pandas reportlab
.\.venv\Scripts\python.exe app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in a browser. The server listens on localhost and is intended for local demonstration.

## CSV format

CSV files must contain these columns:

| Column | Required | Description |
| --- | --- | --- |
| `timestamp` | Yes | Event date and time parseable by pandas |
| `event_type` | Yes | Event name used by the detection rules |
| `source_ip` | Yes | Source address or an identifier such as `unknown` |
| `user` | No | Account name; defaults to `unknown` |
| `device` | No | Device or host name; defaults to `unknown` |
| `status` | No | Event status; defaults to `unknown` |
| `details` | No | Additional event or command context; defaults to `unknown` |

Column names are case-insensitive and surrounding whitespace is ignored. The engine recognizes these event types for specific rules:

```text
failed_login
successful_login
powershell_process_start
privilege_change
malware_alert
ransomware_alert
unusual_access
```

Other event types are still included in the analysis but receive no event-specific rule score. Map IBM Z event names to the canonical names above where they represent the same behavior; preserve the original source data separately if exact source terminology is important.

Example:

```csv
timestamp,event_type,source_ip,user,device,status,details
2026-10-17 09:00:00,failed_login,192.0.2.25,analyst1,z-host-01,failed,Invalid password
2026-10-17 09:01:00,successful_login,192.0.2.25,analyst1,z-host-01,success,Login after repeated failures
```

## IBM Z datathon use

Use the application as a demonstration layer in a wider IBM Z security-log workflow:

1. Select authorized security or system events relevant to the demonstration.
2. Export or transform them outside this application into the CSV schema above.
3. Map source event names to the supported canonical event types when appropriate.
4. Upload the prepared CSV, inspect the explanations and incident timelines, and validate findings against the original records.

The project currently has no native z/OS, SMF, mainframe data-stream, or IBM Z API integration. A production integration would need an approved collection/export pipeline, event-specific parsing and mappings, access controls, durable evidence storage, and operational security review.

## API endpoints

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/health` | Basic application health response |
| `POST` | `/api/analyze/sample` | Analyze `sample_logs.csv` |
| `POST` | `/api/analyze/upload` | Analyze an uploaded CSV using the multipart field `file` |
| `GET` | `/api/incidents` | Get the current analysis summary, events, and incidents |
| `POST` | `/api/incidents/<incident_id>/status` | Set an incident status to `Pending`, `Approved`, or `Done` |
| `GET` | `/api/incidents/<incident_id>/report.pdf` | Download an incident report after marking it `Done` |
| `GET` | `/api/report/full.pdf` | Download a full-analysis PDF |
| `GET` | `/api/verify` | Verify the current in-memory evidence chain |

## Demo limitations and data handling

- This is a prototype, not a production security monitoring or incident-response system.
- It has no authentication or authorization. The local server should not be exposed to an untrusted network.
- Analysis results and incident review statuses are held in memory and reset when the server restarts.
- IP and user masking applies to displayed/exported findings; treat uploaded source logs as sensitive and use only data authorized for the demo.
- Detection rules and scores are illustrative. Analysts must verify findings against original logs and other evidence before taking action.
