"""Central configuration. Every value can be overridden with an SLA_* env variable."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _int(name, default):
    return int(os.getenv(name, default))


DB_PATH = Path(os.getenv("SLA_DB_PATH", BASE_DIR / "data" / "security.db"))
WATCH_DIR = Path(os.getenv("SLA_WATCH_DIR", BASE_DIR / "logs"))
ALERT_LOG = Path(os.getenv("SLA_ALERT_LOG", BASE_DIR / "data" / "alerts.log"))
BLACKLIST_FILE = Path(os.getenv("SLA_BLACKLIST", BASE_DIR / "config" / "blacklist.txt"))
POLL_INTERVAL = float(os.getenv("SLA_POLL_INTERVAL", "1.0"))
API_KEY = os.getenv("SLA_API_KEY", "")  # empty = auth disabled

# ---- Detection thresholds ----
FAILED_LOGIN_THRESHOLD = _int("SLA_FAILED_THRESHOLD", 5)      # failures ...
FAILED_LOGIN_WINDOW = _int("SLA_FAILED_WINDOW", 120)          # ... within N seconds
ENUM_USER_THRESHOLD = _int("SLA_ENUM_USERS", 4)               # distinct usernames from one IP
WEB_ERROR_THRESHOLD = _int("SLA_WEB_ERRORS", 10)              # 4xx responses ...
WEB_ERROR_WINDOW = _int("SLA_WEB_WINDOW", 60)                 # ... within N seconds
COMPROMISE_FAILURES = _int("SLA_COMPROMISE_FAILURES", 3)      # failures before a success
OFF_HOURS_START = _int("SLA_OFF_START", 22)                   # 22:00
OFF_HOURS_END = _int("SLA_OFF_END", 5)                        # 05:00
ALERT_COOLDOWN = _int("SLA_COOLDOWN", 300)                    # seconds between duplicate alerts


def load_blacklist():
    ips = {i.strip() for i in os.getenv("SLA_BLACKLIST_IPS", "").split(",") if i.strip()}
    if BLACKLIST_FILE.exists():
        for line in BLACKLIST_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ips.add(line)
    return ips


# ---- Notifications (all optional) ----
SMTP_HOST = os.getenv("SLA_SMTP_HOST", "")
SMTP_PORT = _int("SLA_SMTP_PORT", 587)
SMTP_USER = os.getenv("SLA_SMTP_USER", "")
SMTP_PASS = os.getenv("SLA_SMTP_PASS", "")
EMAIL_FROM = os.getenv("SLA_EMAIL_FROM", SMTP_USER)
EMAIL_TO = [e.strip() for e in os.getenv("SLA_EMAIL_TO", "").split(",") if e.strip()]
NOTIFY_MIN_SEVERITY = os.getenv("SLA_NOTIFY_MIN_SEVERITY", "HIGH")
WEBHOOK_URL = os.getenv("SLA_WEBHOOK_URL", "")  # Slack/Discord/Teams-style {"text": ...}
