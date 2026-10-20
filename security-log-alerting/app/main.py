"""FastAPI backend: health/status, ingestion, alerts, stats, reports, ML."""
import csv
import io
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

from . import config
from . import database as db
from . import ml, pipeline
from .monitor import LogMonitor

monitor = LogMonitor()
STARTED = time.time()


@asynccontextmanager
async def lifespan(_):
    db.init_db()
    monitor.start()
    yield
    monitor.stop()


def auth(x_api_key: str = Header(default="")):
    if config.API_KEY and x_api_key != config.API_KEY:
        raise HTTPException(401, "Invalid API key")


app = FastAPI(title="Security Log Analysis & Alerting System", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class IngestBody(BaseModel):
    lines: list[str]
    source: str = "api"


@app.get("/")
def root():
    return {"name": app.title, "docs": "/docs"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/status", dependencies=[Depends(auth)])
def status():
    return {"monitor_running": monitor.is_alive(), "watch_dir": str(monitor.watch_dir),
            "uptime_seconds": int(time.time() - STARTED), "counters": pipeline.COUNTERS,
            "watched_files": list(monitor.files), "api_auth": bool(config.API_KEY),
            "thresholds": {"failed_logins": config.FAILED_LOGIN_THRESHOLD,
                           "window_s": config.FAILED_LOGIN_WINDOW}}


@app.get("/stats", dependencies=[Depends(auth)])
def stats():
    return db.stats()


@app.get("/events", dependencies=[Depends(auth)])
def events(limit: int = 200, event_type: str | None = None, ip: str | None = None):
    return db.get_events(min(limit, 2000), event_type, ip)


@app.get("/alerts", dependencies=[Depends(auth)])
def alerts(limit: int = 200, severity: str | None = None, acknowledged: bool | None = None):
    return db.get_alerts(min(limit, 2000), severity, acknowledged)


@app.post("/alerts/{alert_id}/ack", dependencies=[Depends(auth)])
def ack(alert_id: int):
    db.ack_alert(alert_id)
    return {"acknowledged": alert_id}


@app.post("/ingest", dependencies=[Depends(auth)])
def ingest(body: IngestBody):
    return pipeline.process_lines(body.lines, body.source)


@app.post("/upload", dependencies=[Depends(auth)])
async def upload(file: UploadFile = File(...)):
    text = (await file.read()).decode("utf-8", "replace")
    return pipeline.process_lines(text.splitlines(), file.filename or "upload")


@app.get("/report", dependencies=[Depends(auth)])
def report():
    buf = io.StringIO()
    rows = db.get_alerts(10000)
    w = csv.writer(buf)
    w.writerow(["id", "event_ts", "severity", "rule", "ip", "username", "description", "acknowledged"])
    for r in rows:
        w.writerow([r["id"], r["event_ts"], r["severity"], r["rule"], r["ip"], r["username"],
                    r["description"], r["acknowledged"]])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=alert_report.csv"})


@app.get("/ml/anomalies", dependencies=[Depends(auth)])
def ml_anomalies(contamination: float = 0.05):
    return ml.detect_anomalies(contamination)
