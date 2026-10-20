"""Log simulator. Writes realistic SSH + web logs into logs/live/ so the monitor reacts in real time.

  python scripts/generate_logs.py --demo          # one burst containing every attack type
  python scripts/generate_logs.py --interval 2    # continuous mix of normal traffic and random attacks
"""
import argparse
import random
import time
from datetime import datetime
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "logs" / "live"
OUT.mkdir(parents=True, exist_ok=True)
AUTH, WEB = OUT / "auth.log", OUT / "access.log"
USERS = ["alice", "bob", "carol", "dave"]
INTERNAL = ["10.0.0.11", "10.0.0.12", "10.0.0.25", "192.168.1.40"]
ATTACKERS = ["45.133.1.77", "185.220.101.5", "91.240.118.9", "203.0.113.66"]
PATHS = ["/", "/index.html", "/login", "/api/items", "/static/app.js", "/about"]
ATTACK_PATHS = ["/.env", "/wp-login.php", "/phpmyadmin/", "/../../etc/passwd",
                "/search?q=1' OR 1=1--", "/item?id=1 UNION SELECT password FROM users"]


def ssh(msg, host="web01"):
    with open(AUTH, "a") as f:
        f.write(f"{datetime.now():%b %d %H:%M:%S} {host} sshd[{random.randint(1000, 9999)}]: {msg}\n")


def web(ip, path, status):
    with open(WEB, "a") as f:
        f.write(f'{ip} - - [{datetime.now().astimezone():%d/%b/%Y:%H:%M:%S %z}] '
                f'"GET {path.replace(" ", "%20")} HTTP/1.1" {status} {random.randint(200, 5000)}\n')


def normal():
    ip = random.choice(INTERNAL)
    if random.random() < .3:
        ssh(f"Accepted password for {random.choice(USERS)} from {ip} port {random.randint(30000, 60000)} ssh2")
    web(ip, random.choice(PATHS), random.choice([200, 200, 200, 304]))


def brute_force(ip=None, n=8):
    ip = ip or random.choice(ATTACKERS)
    for _ in range(n):
        ssh(f"Failed password for root from {ip} port {random.randint(30000, 60000)} ssh2")
    return ip


def enumeration():
    ip = random.choice(ATTACKERS)
    for u in ["admin", "test", "oracle", "ubuntu", "postgres"]:
        ssh(f"Invalid user {u} from {ip} port {random.randint(30000, 60000)}")
        ssh(f"Failed password for invalid user {u} from {ip} port {random.randint(30000, 60000)} ssh2")


def compromise():
    ip = brute_force("185.220.101.5", 4)
    ssh(f"Accepted password for bob from {ip} port 41022 ssh2")


def web_scan():
    ip = random.choice(ATTACKERS)
    for i in range(12):
        web(ip, f"/admin{i}", 404)


def injection():
    ip = random.choice(ATTACKERS)
    for p in random.sample(ATTACK_PATHS, 3):
        web(ip, p, random.choice([200, 403, 404]))


ATTACKS = [brute_force, enumeration, compromise, web_scan, injection]

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--attack-chance", type=float, default=0.15)
    a = ap.parse_args()
    if a.demo:
        for _ in range(10):
            normal()
        for fn in ATTACKS:
            print("running", fn.__name__)
            fn()
        print("demo logs written to", OUT)
    else:
        print("Generating logs in", OUT, "- Ctrl+C to stop")
        while True:
            normal()
            if random.random() < a.attack_chance:
                fn = random.choice(ATTACKS)
                print("attack:", fn.__name__)
                fn()
            time.sleep(a.interval)
