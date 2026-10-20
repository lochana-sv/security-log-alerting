"""Streamlit security monitoring dashboard."""
import os
import time

import pandas as pd
import requests
import streamlit as st

st.set_page_config(page_title="Security Log Analysis & Alerting", page_icon="🛡️", layout="wide")
ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

st.sidebar.title("🛡️ Settings")
API = st.sidebar.text_input("API URL", os.getenv("SLA_API_URL", "http://127.0.0.1:8000"))
KEY = st.sidebar.text_input("API key (if enabled)", os.getenv("SLA_API_KEY", ""), type="password")
auto = st.sidebar.checkbox("Auto-refresh", True)
every = st.sidebar.slider("Refresh every (s)", 2, 30, 5)
sev_filter = st.sidebar.multiselect("Severity", list(ICON), default=list(ICON))
show_open = st.sidebar.checkbox("Only unacknowledged", False)


def call(method, path, **kw):
    try:
        r = requests.request(method, API + path, headers={"X-API-Key": KEY}, timeout=10, **kw)
        r.raise_for_status()
        return r
    except Exception as exc:
        st.error(f"Backend not reachable / request failed: {exc}")
        return None


def get(path, **params):
    r = call("GET", path, params=params)
    return r.json() if r else None


st.title("🛡️ Security Log Analysis & Alerting System")
health = get("/health")
status = get("/status")
if not (health and status):
    st.warning("Start the backend first:  `uvicorn app.main:app --port 8000`")
    st.stop()

stats = get("/stats") or {}
alerts = get("/alerts", limit=500) or []
st.caption(f"Monitor: {'🟢 running' if status['monitor_running'] else '🔴 stopped'} · "
           f"watching `{status['watch_dir']}` · {len(status['watched_files'])} file(s) · "
           f"uptime {status['uptime_seconds']}s")

tab_over, tab_alerts, tab_logs, tab_ingest, tab_ml = st.tabs(
    ["📊 Overview", "🚨 Alerts", "📜 Logs", "⬆️ Ingest", "🤖 ML anomalies"])

with tab_over:
    sev = {r["severity"]: r["n"] for r in stats.get("alerts_by_severity", [])}
    c = st.columns(6)
    c[0].metric("Events", stats.get("total_events", 0))
    c[1].metric("Failed logins", stats.get("failed_logins", 0))
    c[2].metric("Open alerts", stats.get("open_alerts", 0))
    c[3].metric("🔴 Critical", sev.get("CRITICAL", 0))
    c[4].metric("🟠 High", sev.get("HIGH", 0))
    c[5].metric("🟡 Medium", sev.get("MEDIUM", 0))
    l, r = st.columns(2)
    with l:
        st.subheader("Failed logins over time")
        t = pd.DataFrame(stats.get("timeline", []))
        if not t.empty:
            st.line_chart(t.sort_values("bucket").set_index("bucket")["n"])
        else:
            st.info("No failed logins yet.")
        st.subheader("Alerts by rule")
        a = pd.DataFrame(stats.get("alerts_by_rule", []))
        if not a.empty:
            st.bar_chart(a.set_index("rule")["n"])
    with r:
        st.subheader("Top suspicious IPs")
        ips = pd.DataFrame(stats.get("top_ips", []))
        if not ips.empty:
            st.bar_chart(ips.set_index("ip")["n"])
        st.subheader("Events by type")
        e = pd.DataFrame(stats.get("events_by_type", []))
        if not e.empty:
            st.dataframe(e, use_container_width=True, hide_index=True)

with tab_alerts:
    rows = [a for a in alerts if a["severity"] in sev_filter and not (show_open and a["acknowledged"])]
    if rows:
        df = pd.DataFrame(rows)
        df.insert(0, "sev", df["severity"].map(ICON))
        st.dataframe(df[["id", "sev", "severity", "rule", "ip", "username", "description",
                         "event_ts", "acknowledged"]], use_container_width=True, hide_index=True)
        ids = st.multiselect("Acknowledge alerts", [a["id"] for a in rows if not a["acknowledged"]])
        if st.button("✅ Acknowledge selected") and ids:
            for i in ids:
                call("POST", f"/alerts/{i}/ack")
            st.rerun()
        r = call("GET", "/report")
        if r:
            st.download_button("⬇️ Download CSV report", r.content, "alert_report.csv", "text/csv")
    else:
        st.success("No alerts match the current filters.")

with tab_logs:
    f1, f2, f3 = st.columns(3)
    et = f1.selectbox("Event type", ["", "login_failed", "login_success", "invalid_user",
                                     "web_request", "sudo"])
    ip = f2.text_input("IP filter")
    lim = f3.slider("Rows", 50, 1000, 200)
    ev = get("/events", limit=lim, event_type=et or None, ip=ip or None)
    if ev:
        st.dataframe(pd.DataFrame(ev), use_container_width=True, hide_index=True)

with tab_ingest:
    st.write("Upload a log file (OpenSSH auth log, Apache/Nginx access log, or "
             "`YYYY-MM-DD HH:MM:SS EVENT key=value` format) or paste lines.")
    up = st.file_uploader("Log file", type=["log", "txt"])
    if up and st.button("Analyse file"):
        r = call("POST", "/upload", files={"file": (up.name, up.getvalue())})
        if r:
            st.success(r.json())
    txt = st.text_area("Paste log lines", height=120)
    if st.button("Analyse pasted lines") and txt.strip():
        r = call("POST", "/ingest", json={"lines": txt.splitlines(), "source": "paste"})
        if r:
            st.success(r.json())

with tab_ml:
    cont = st.slider("Contamination (expected anomaly share)", 0.01, 0.2, 0.05)
    m = get("/ml/anomalies", contamination=cont)
    if m:
        if m.get("anomalies"):
            st.dataframe(pd.DataFrame(m["anomalies"]), use_container_width=True, hide_index=True)
        else:
            st.info(m.get("message", "No anomalies."))

if auto:
    time.sleep(every)
    st.rerun()
