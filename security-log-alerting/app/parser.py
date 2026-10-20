"""Log pre-processing: turn raw lines into structured event dicts."""
import re
from datetime import datetime, timedelta

IP = r"[0-9a-fA-F:.]+"
SYSLOG = (r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
          r"\s+(?P<host>\S+)\s+")

RE_SSH_FAILED = re.compile(SYSLOG + rf"sshd(?:\[\d+\])?:\s+Failed (?:password|publickey) for "
                           rf"(?:invalid user )?(?P<user>\S+) from (?P<ip>{IP})")
RE_SSH_OK = re.compile(SYSLOG + rf"sshd(?:\[\d+\])?:\s+Accepted (?:password|publickey) for "
                       rf"(?P<user>\S+) from (?P<ip>{IP})")
RE_SSH_INVALID = re.compile(SYSLOG + rf"sshd(?:\[\d+\])?:\s+Invalid user (?P<user>\S*) from (?P<ip>{IP})")
RE_SUDO = re.compile(SYSLOG + r"sudo(?:\[\d+\])?:\s+(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.*)$")
RE_WEB = re.compile(r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
                    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: [^"]*)?" (?P<status>\d{3}) (?P<size>\S+)')
RE_GENERIC = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+(?P<etype>[A-Za-z_]+)\s*(?P<rest>.*)$")
RE_KV = re.compile(r'(\w+)=("[^"]*"|\S+)')


def _syslog_ts(mon, day, tm):
    now = datetime.now()
    ts = datetime.strptime(f"{now.year} {mon} {int(day)} {tm}", "%Y %b %d %H:%M:%S")
    if ts - now > timedelta(days=1):  # log from last December
        ts = ts.replace(year=now.year - 1)
    return ts


def _event(ts, source, etype, raw, **kw):
    return {"ts": ts.replace(microsecond=0).isoformat(), "source": source, "host": kw.get("host"),
            "ip": kw.get("ip"), "username": kw.get("user"), "event_type": etype,
            "status": kw.get("status"), "method": kw.get("method"), "path": kw.get("path"),
            "message": kw.get("message", raw[:200]), "raw": raw}


def parse_line(line, source=""):
    """Return a structured event dict, or None if the line is not recognised."""
    line = line.rstrip("\r\n")
    if not line.strip():
        return None

    for rx, etype in ((RE_SSH_FAILED, "login_failed"), (RE_SSH_OK, "login_success"),
                      (RE_SSH_INVALID, "invalid_user")):
        m = rx.match(line)
        if m:
            return _event(_syslog_ts(m["mon"], m["day"], m["time"]), source, etype, line,
                          host=m["host"], ip=m["ip"], user=m["user"])

    m = RE_SUDO.match(line)
    if m:
        return _event(_syslog_ts(m["mon"], m["day"], m["time"]), source, "sudo", line,
                      host=m["host"], user=m["user"], message=f"sudo: {m['cmd'][:120]}")

    m = RE_WEB.match(line)
    if m:
        try:
            ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").astimezone().replace(tzinfo=None)
        except ValueError:
            return None
        user = None if m["user"] == "-" else m["user"]
        return _event(ts, source, "web_request", line, ip=m["ip"], user=user, method=m["method"],
                      path=m["path"], status=int(m["status"]),
                      message=f'{m["method"]} {m["path"]} -> {m["status"]}')

    m = RE_GENERIC.match(line)
    if m:
        try:
            ts = datetime.fromisoformat(m["ts"].replace(" ", "T"))
        except ValueError:
            return None
        kv = {k: v.strip('"') for k, v in RE_KV.findall(m["rest"])}
        etype = m["etype"].lower()
        return _event(ts, source, etype, line, ip=kv.get("ip"), user=kv.get("user"),
                      status=int(kv["status"]) if kv.get("status", "").isdigit() else None,
                      path=kv.get("path"), host=kv.get("host"))
    return None
