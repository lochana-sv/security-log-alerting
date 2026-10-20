# Security Log Analysis and Alerting System

Automated collection, analysis and alerting for security logs (Dept of CSE, AIT Tumakuru, 2026-27).
Implements every stage of the report's methodology.

| Report stage | Implementation |
|---|---|
| 1. Log collection | `app/monitor.py` tails `logs/**/*.log` in real time; `/ingest` and `/upload` API; dashboard upload |
| 2. Pre-processing | `app/parser.py`: OpenSSH auth, sudo, Apache/Nginx access, generic `key=value` logs -> structured events |
| 3. Log analysis | `app/pipeline.py` (parse -> store -> detect) |
| 4. Threat detection | `app/detector.py` rules + thresholds; `app/ml.py` IsolationForest (future-work item) |
| 5. Alert generation | `app/alerts.py`: console, `data/alerts.log`, optional e-mail and webhook |
| 6. Dashboard | `dashboard.py` (Streamlit) |
| 7. Storage & reporting | SQLite (`data/security.db`), acknowledgement workflow, CSV report |

## Detection rules
| Rule | Severity | Trigger |
|---|---|---|
| BRUTE_FORCE | HIGH | >= 5 failed logins from one IP in 120 s |
| USER_ENUMERATION | MEDIUM | >= 4 distinct usernames from one IP in 120 s |
| POSSIBLE_COMPROMISE | CRITICAL | successful login after >= 3 recent failures |
| ROOT_LOGIN | HIGH | direct root login |
| OFF_HOURS_LOGIN | LOW | login between 22:00 and 05:00 |
| BLACKLISTED_IP | HIGH | any activity from an IP in `config/blacklist.txt` |
| WEB_SCAN | MEDIUM | >= 10 HTTP 4xx from one IP in 60 s |
| SUSPICIOUS_REQUEST | HIGH | SQLi / traversal / `.env` / XSS patterns in URL |

All thresholds are env-configurable (`app/config.py`, e.g. `SLA_FAILED_THRESHOLD=3`). Duplicate alerts are suppressed by a 5-minute cooldown.

## Quick start (Python 3.10+)
```bash
python -m venv venv && source venv/bin/activate     # Windows: venv\Scripts\activate
pip install -r requirements.txt

python run.py                                        # backend :8000 + dashboard :8501
# in another terminal, generate live traffic and attacks:
python scripts/generate_logs.py --demo               # one burst of every attack type
python scripts/generate_logs.py --interval 2         # continuous simulation
```
Open http://localhost:8501 (dashboard) and http://localhost:8000/docs (API docs).
Or run separately: `uvicorn app.main:app --port 8000` and `streamlit run dashboard.py`.

To monitor real logs, set `SLA_WATCH_DIR` to a folder containing `*.log` files
(e.g. copies/symlinks of `/var/log/auth.log` as `auth.log`, nginx `access.log`).

## API
`GET /health` `GET /status` `GET /stats` `GET /events` `GET /alerts` `POST /alerts/{id}/ack`
`POST /ingest` `POST /upload` `GET /report` (CSV) `GET /ml/anomalies`.
Set `SLA_API_KEY` to require an `X-API-Key` header.

## Notifications (optional)
`SLA_SMTP_HOST, SLA_SMTP_PORT, SLA_SMTP_USER, SLA_SMTP_PASS, SLA_EMAIL_TO` for e-mail;
`SLA_WEBHOOK_URL` for Slack/Teams/Discord. `SLA_NOTIFY_MIN_SEVERITY` (default HIGH).

## Tests
`python -m unittest discover -s tests -t .`

## Project layout
```
app/ (config, parser, detector, database, alerts, pipeline, monitor, ml, main)
dashboard.py   run.py   scripts/generate_logs.py   tests/   config/blacklist.txt
logs/  data/   requirements.txt
```
