"""Real-time monitor: tails every *.log under WATCH_DIR and feeds the pipeline."""
import threading
from pathlib import Path

from . import config
from . import database as db
from . import pipeline


class LogMonitor(threading.Thread):
    def __init__(self, watch_dir=None, interval=None):
        super().__init__(daemon=True, name="log-monitor")
        self.watch_dir = Path(watch_dir or config.WATCH_DIR)
        self.interval = interval or config.POLL_INTERVAL
        self._stop_evt = threading.Event()
        self.files = {}

    def stop(self):
        self._stop_evt.set()

    def run(self):
        while not self._stop_evt.is_set():
            try:
                self.scan_once()
            except Exception as exc:
                print("monitor error:", exc)
            self._stop_evt.wait(self.interval)

    def scan_once(self):
        if not self.watch_dir.exists():
            return
        for p in sorted(self.watch_dir.rglob("*.log")):
            self._read(p)

    def _read(self, p):
        key = str(p)
        size = p.stat().st_size
        off = self.files.get(key)
        if off is None:
            off = db.get_offset(key)
        if size < off:       # file rotated / truncated
            off = 0
        if size == off:
            self.files[key] = off
            return
        with open(p, "rb") as f:
            f.seek(off)
            data = f.read()
        end = data.rfind(b"\n")
        if end == -1:        # incomplete line, wait for more
            return
        chunk = data[: end + 1]
        for line in chunk.decode("utf-8", "replace").splitlines():
            pipeline.process_line(line, source=p.name)
        self.files[key] = off + len(chunk)
        db.set_offset(key, self.files[key])
