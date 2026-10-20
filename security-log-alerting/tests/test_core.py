import os
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from app.detector import Detector
from app.parser import parse_line


def ssh_line(ts, msg):
    return f"{ts:%b %d %H:%M:%S} web01 sshd[1234]: {msg}"


class ParserTests(unittest.TestCase):
    def test_ssh_failed(self):
        e = parse_line(ssh_line(datetime.now(), "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"))
        self.assertEqual((e["event_type"], e["ip"], e["username"]), ("login_failed", "1.2.3.4", "admin"))

    def test_ssh_accepted(self):
        e = parse_line(ssh_line(datetime.now(), "Accepted publickey for bob from 10.0.0.1 port 22 ssh2"))
        self.assertEqual(e["event_type"], "login_success")

    def test_web(self):
        e = parse_line('9.9.9.9 - - [19/Oct/2026:10:00:00 +0000] "GET /.env HTTP/1.1" 404 120')
        self.assertEqual((e["event_type"], e["status"], e["path"]), ("web_request", 404, "/.env"))

    def test_generic(self):
        e = parse_line("2026-10-19 10:00:00 LOGIN_FAILED user=eve ip=5.5.5.5")
        self.assertEqual((e["event_type"], e["ip"], e["username"]), ("login_failed", "5.5.5.5", "eve"))

    def test_garbage(self):
        self.assertIsNone(parse_line("this is not a log line"))


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.d = Detector(BLACKLIST={"6.6.6.6"})
        self.t0 = datetime(2026, 10, 19, 12, 0, 0)

    def ev(self, secs, etype, ip="1.1.1.1", user="root", **kw):
        return {"ts": (self.t0 + timedelta(seconds=secs)).isoformat(), "event_type": etype,
                "ip": ip, "username": user, "status": kw.get("status"), "path": kw.get("path")}

    def rules(self, events):
        return [a["rule"] for e in events for a in self.d.process(e)]

    def test_brute_force(self):
        r = self.rules([self.ev(i, "login_failed") for i in range(6)])
        self.assertEqual(r.count("BRUTE_FORCE"), 1)       # cooldown prevents duplicates

    def test_slow_attempts_no_alert(self):
        self.assertNotIn("BRUTE_FORCE", self.rules([self.ev(i * 100, "login_failed") for i in range(6)]))

    def test_compromise(self):
        evs = [self.ev(i, "login_failed") for i in range(4)] + [self.ev(5, "login_success", user="bob")]
        self.assertIn("POSSIBLE_COMPROMISE", self.rules(evs))

    def test_enumeration(self):
        evs = [self.ev(i, "invalid_user", user=u) for i, u in enumerate(["a", "b", "c", "d"])]
        self.assertIn("USER_ENUMERATION", self.rules(evs))

    def test_blacklist(self):
        self.assertIn("BLACKLISTED_IP", self.rules([self.ev(0, "web_request", ip="6.6.6.6", status=200)]))

    def test_web_scan_and_injection(self):
        evs = [self.ev(i, "web_request", status=404, path=f"/x{i}") for i in range(10)]
        self.assertIn("WEB_SCAN", self.rules(evs))
        self.assertIn("SUSPICIOUS_REQUEST", self.rules(
            [self.ev(0, "web_request", ip="2.2.2.2", status=200, path="/a?id=1 UNION SELECT x")]))

    def test_off_hours_and_root(self):
        e = self.ev(0, "login_success", user="root")
        e["ts"] = datetime(2026, 10, 19, 3, 0).isoformat()
        r = self.rules([e])
        self.assertIn("OFF_HOURS_LOGIN", r)
        self.assertIn("ROOT_LOGIN", r)


class PipelineTests(unittest.TestCase):
    def test_end_to_end(self):
        from app import database as db, pipeline
        with tempfile.TemporaryDirectory() as td:
            db.init_db(Path(td) / "t.db")
            now = datetime.now()
            lines = [ssh_line(now, "Failed password for root from 8.8.8.8 port 22 ssh2")] * 6
            res = pipeline.process_lines(lines, "test")
            self.assertEqual(res["parsed"], 6)
            self.assertGreaterEqual(res["alerts_raised"], 1)
            self.assertEqual(db.get_alerts()[0]["rule"], "BRUTE_FORCE")
            self.assertEqual(db.stats()["failed_logins"], 6)
            db.init_db(Path(td) / "other.db")   # release the temp file before cleanup


if __name__ == "__main__":
    unittest.main()
