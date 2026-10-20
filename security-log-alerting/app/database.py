"""SQLite storage for events, alerts and file offsets (secure, centralised log store)."""
import json
import sqlite3
import threading

from . import config

_lock = threading.RLock()
_conn = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, source TEXT, host TEXT, ip TEXT,
  username TEXT, event_type TEXT, status INTEGER, method TEXT, path TEXT, message TEXT, raw TEXT);
CREATE INDEX IF NOT EXISTS ix_ev_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_ev_ip ON events(ip);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT DEFAULT (datetime('now','localtime')),
  event_ts TEXT, rule TEXT, severity TEXT, ip TEXT, username TEXT, description TEXT,
  details TEXT, acknowledged INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_al_sev ON alerts(severity);
CREATE TABLE IF NOT EXISTS offsets(path TEXT PRIMARY KEY, offset INTEGER);
"""


def init_db(path=None):
    global _conn
    with _lock:
        if _conn is not None:
            _conn.close()
        p = path or config.DB_PATH
        p.parent.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(p, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.executescript(SCHEMA)
        _conn.commit()


def _c():
    if _conn is None:
        init_db()
    return _conn


def execute(sql, params=()):
    with _lock:
        cur = _c().execute(sql, params)
        _c().commit()
        return cur.lastrowid


def fetch(sql, params=()):
    with _lock:
        return [dict(r) for r in _c().execute(sql, params).fetchall()]


def insert_event(e):
    return execute(
        "INSERT INTO events(ts,source,host,ip,username,event_type,status,method,path,message,raw)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (e["ts"], e["source"], e["host"], e["ip"], e["username"], e["event_type"], e["status"],
         e["method"], e["path"], e["message"], e["raw"]))


def insert_alert(a):
    return execute(
        "INSERT INTO alerts(event_ts,rule,severity,ip,username,description,details) VALUES(?,?,?,?,?,?,?)",
        (a["event_ts"], a["rule"], a["severity"], a["ip"], a["username"], a["description"],
         json.dumps(a.get("details", {}))))


def get_events(limit=200, event_type=None, ip=None):
    sql, p = "SELECT id,ts,source,ip,username,event_type,status,path,message FROM events WHERE 1=1", []
    if event_type:
        sql += " AND event_type=?"; p.append(event_type)
    if ip:
        sql += " AND ip=?"; p.append(ip)
    return fetch(sql + " ORDER BY id DESC LIMIT ?", (*p, limit))


def get_alerts(limit=200, severity=None, acknowledged=None):
    sql, p = "SELECT * FROM alerts WHERE 1=1", []
    if severity:
        sql += " AND severity=?"; p.append(severity.upper())
    if acknowledged is not None:
        sql += " AND acknowledged=?"; p.append(int(acknowledged))
    rows = fetch(sql + " ORDER BY id DESC LIMIT ?", (*p, limit))
    for r in rows:
        r["details"] = json.loads(r["details"] or "{}")
    return rows


def ack_alert(alert_id):
    execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))


def get_offset(path):
    r = fetch("SELECT offset FROM offsets WHERE path=?", (path,))
    return r[0]["offset"] if r else 0


def set_offset(path, off):
    execute("INSERT INTO offsets(path,offset) VALUES(?,?) ON CONFLICT(path) DO UPDATE SET offset=?",
            (path, off, off))


def stats():
    one = lambda q: fetch(q)[0]["n"]
    return {
        "total_events": one("SELECT COUNT(*) n FROM events"),
        "total_alerts": one("SELECT COUNT(*) n FROM alerts"),
        "open_alerts": one("SELECT COUNT(*) n FROM alerts WHERE acknowledged=0"),
        "failed_logins": one("SELECT COUNT(*) n FROM events WHERE event_type='login_failed'"),
        "alerts_by_severity": fetch("SELECT severity, COUNT(*) n FROM alerts GROUP BY severity"),
        "alerts_by_rule": fetch("SELECT rule, COUNT(*) n FROM alerts GROUP BY rule ORDER BY n DESC"),
        "events_by_type": fetch("SELECT event_type, COUNT(*) n FROM events GROUP BY event_type ORDER BY n DESC"),
        "top_ips": fetch("SELECT ip, COUNT(*) n FROM events WHERE ip IS NOT NULL AND (event_type IN "
                         "('login_failed','invalid_user') OR status>=400) GROUP BY ip ORDER BY n DESC LIMIT 10"),
        "timeline": fetch("SELECT substr(ts,1,15)||'0' AS bucket, COUNT(*) n FROM events WHERE event_type IN "
                          "('login_failed','invalid_user') GROUP BY bucket ORDER BY bucket DESC LIMIT 72"),
    }
