"""parse -> store -> detect -> alert. Shared by the file monitor and the API."""
import threading

from . import alerts as alert_mod
from . import database as db
from .detector import Detector
from .parser import parse_line

_detector = Detector()
_lock = threading.Lock()
COUNTERS = {"processed": 0, "skipped": 0, "alerts": 0}


def process_line(line, source=""):
    ev = parse_line(line, source)
    if ev is None:
        if line.strip():
            COUNTERS["skipped"] += 1
        return None
    with _lock:
        ev_id = db.insert_event(ev)
        found = _detector.process(ev)
        for a in found:
            a["id"] = db.insert_alert(a)
    for a in found:
        alert_mod.dispatch(a)
    COUNTERS["processed"] += 1
    COUNTERS["alerts"] += len(found)
    return {"event_id": ev_id, "alerts": found}


def process_lines(lines, source="api"):
    n = a = 0
    for line in lines:
        r = process_line(line, source)
        if r:
            n += 1
            a += len(r["alerts"])
    return {"parsed": n, "alerts_raised": a, "skipped": len(lines) - n}
