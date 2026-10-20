"""Rule/threshold based threat detection (stateful, works on event timestamps)."""
import re
from collections import defaultdict, deque
from datetime import datetime

from . import config

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
FAIL_TYPES = {"login_failed", "invalid_user"}

SUSPICIOUS_PATH = re.compile(
    r"(\.\./|%2e%2e|/etc/passwd|union(\s|%20|\+)+select|<script|%3cscript|\.env\b|"
    r"phpmyadmin|wp-login|cmd\.exe|or(\s|%20|\+)+1=1|'--|;\s*(cat|ls|wget|curl)\b)", re.I)


class Detector:
    def __init__(self, **overrides):
        c = {k: getattr(config, k) for k in (
            "FAILED_LOGIN_THRESHOLD", "FAILED_LOGIN_WINDOW", "ENUM_USER_THRESHOLD",
            "WEB_ERROR_THRESHOLD", "WEB_ERROR_WINDOW", "COMPROMISE_FAILURES",
            "OFF_HOURS_START", "OFF_HOURS_END", "ALERT_COOLDOWN")}
        c.update({k: v for k, v in overrides.items() if k in c})
        self.c = c
        self.blacklist = overrides.get("BLACKLIST", config.load_blacklist())
        self.failed = defaultdict(deque)   # ip -> (ts, user) of failed passwords
        self.users = defaultdict(deque)    # ip -> (ts, user) of any failed/invalid attempt
        self.web_err = defaultdict(deque)  # ip -> ts of 4xx responses
        self.last_alert = {}

    # ---- helpers ----
    @staticmethod
    def _prune(dq, now, window, key=lambda x: x):
        while dq and (now - key(dq[0])).total_seconds() > window:
            dq.popleft()

    def _alert(self, ts, rule, severity, ev, description, **details):
        key = (rule, ev.get("ip") or ev.get("username"))
        last = self.last_alert.get(key)
        if last and abs((ts - last).total_seconds()) < self.c["ALERT_COOLDOWN"]:
            return None
        self.last_alert[key] = ts
        return {"rule": rule, "severity": severity, "ip": ev.get("ip"),
                "username": ev.get("username"), "event_ts": ev["ts"],
                "description": description, "details": details}

    # ---- main entry ----
    def process(self, ev):
        ts = datetime.fromisoformat(ev["ts"])
        ip, user, et = ev.get("ip"), ev.get("username"), ev["event_type"]
        out = []

        def add(a):
            if a:
                out.append(a)

        if ip and ip in self.blacklist:
            add(self._alert(ts, "BLACKLISTED_IP", "HIGH", ev,
                            f"Activity from blacklisted IP {ip} ({et})"))

        if et in FAIL_TYPES and ip:
            u = self.users[ip]
            u.append((ts, user))
            self._prune(u, ts, self.c["FAILED_LOGIN_WINDOW"], key=lambda x: x[0])
            distinct = {x[1] for x in u if x[1]}
            if len(distinct) >= self.c["ENUM_USER_THRESHOLD"]:
                add(self._alert(ts, "USER_ENUMERATION", "MEDIUM", ev,
                                f"{ip} tried {len(distinct)} different usernames "
                                f"in {self.c['FAILED_LOGIN_WINDOW']}s", usernames=sorted(distinct)[:10]))
        if et == "login_failed" and ip:
            f = self.failed[ip]
            f.append((ts, user))
            self._prune(f, ts, self.c["FAILED_LOGIN_WINDOW"], key=lambda x: x[0])
            if len(f) >= self.c["FAILED_LOGIN_THRESHOLD"]:
                add(self._alert(ts, "BRUTE_FORCE", "HIGH", ev,
                                f"{len(f)} failed logins from {ip} within "
                                f"{self.c['FAILED_LOGIN_WINDOW']}s", attempts=len(f)))

        if et == "login_success":
            f = self.failed.get(ip) if ip else None
            if f:
                self._prune(f, ts, self.c["FAILED_LOGIN_WINDOW"], key=lambda x: x[0])
            if f and len(f) >= self.c["COMPROMISE_FAILURES"]:
                add(self._alert(ts, "POSSIBLE_COMPROMISE", "CRITICAL", ev,
                                f"Successful login for '{user}' from {ip} right after "
                                f"{len(f)} failures", prior_failures=len(f)))
                f.clear()
            if user == "root":
                add(self._alert(ts, "ROOT_LOGIN", "HIGH", ev, f"Direct root login from {ip}"))
            s, e = self.c["OFF_HOURS_START"], self.c["OFF_HOURS_END"]
            if ts.hour >= s or ts.hour < e:
                add(self._alert(ts, "OFF_HOURS_LOGIN", "LOW", ev,
                                f"Login for '{user}' from {ip} at {ts:%H:%M} (off hours)"))

        if et == "web_request" and ip:
            if ev.get("status") and 400 <= ev["status"] < 500:
                w = self.web_err[ip]
                w.append(ts)
                self._prune(w, ts, self.c["WEB_ERROR_WINDOW"])
                if len(w) >= self.c["WEB_ERROR_THRESHOLD"]:
                    add(self._alert(ts, "WEB_SCAN", "MEDIUM", ev,
                                    f"{len(w)} client errors from {ip} in "
                                    f"{self.c['WEB_ERROR_WINDOW']}s (scanning / forced browsing)"))
            if ev.get("path") and SUSPICIOUS_PATH.search(ev["path"]):
                add(self._alert(ts, "SUSPICIOUS_REQUEST", "HIGH", ev,
                                f"Attack pattern in request from {ip}: {ev['path'][:100]}",
                                path=ev["path"]))
        return out
