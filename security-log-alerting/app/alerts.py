"""Alert dispatch: console, alert log file, optional e-mail and webhook."""
import json
import logging
import smtplib
import threading
import urllib.request
from email.message import EmailMessage

from . import config
from .detector import SEVERITY_ORDER

log = logging.getLogger("alerts")
if not log.handlers:
    config.ALERT_LOG.parent.mkdir(parents=True, exist_ok=True)
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(message)s")
    for h in (logging.StreamHandler(), logging.FileHandler(config.ALERT_LOG)):
        h.setFormatter(fmt)
        log.addHandler(h)


def _text(a):
    return (f"[{a['severity']}] {a['rule']} | ip={a.get('ip')} user={a.get('username')} | "
            f"{a['description']} (event time {a['event_ts']})")


def _send_email(a):
    try:
        msg = EmailMessage()
        msg["Subject"] = f"[SECURITY {a['severity']}] {a['rule']}"
        msg["From"], msg["To"] = config.EMAIL_FROM, ", ".join(config.EMAIL_TO)
        msg.set_content(_text(a) + "\n\nDetails: " + json.dumps(a.get("details", {}), indent=2))
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=10) as s:
            s.starttls()
            if config.SMTP_USER:
                s.login(config.SMTP_USER, config.SMTP_PASS)
            s.send_message(msg)
    except Exception as exc:  # never let notification problems break monitoring
        log.warning("email failed: %s", exc)


def _send_webhook(a):
    try:
        req = urllib.request.Request(config.WEBHOOK_URL, json.dumps({"text": _text(a)}).encode(),
                                     {"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10).read()
    except Exception as exc:
        log.warning("webhook failed: %s", exc)


def dispatch(a):
    log.warning(_text(a))
    if SEVERITY_ORDER.get(a["severity"], 0) < SEVERITY_ORDER.get(config.NOTIFY_MIN_SEVERITY, 3):
        return
    if config.SMTP_HOST and config.EMAIL_TO:
        threading.Thread(target=_send_email, args=(a,), daemon=True).start()
    if config.WEBHOOK_URL:
        threading.Thread(target=_send_webhook, args=(a,), daemon=True).start()
