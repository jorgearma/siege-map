#!/usr/bin/env python3
"""
A scripted attack day for the demo, so every detection has something to show.

Writes to the logs the dev stack tails (docker-compose.dev.yml):

    python scripts/demo_scenario.py            # ./logs/auth.log + ./logs/access.log
    python scripts/demo_scenario.py --no-live  # only the backfilled history

What it stages, and what should light up on the dashboard:

  act 1  hours of ordinary background bots        → the baseline the rules need
  act 2  one popular tool, its default wordlist    → Campaigns: "shared tooling" (LOW)
  act 3  a botnet: rare wordlist, one /24, 20 min  → Campaigns: "coordinated campaign" + alert
  act 4  11 machines, one try each, same account   → Campaigns: "distributed spray" + alert
  act 5  a fast dictionary attack from one address → Bot of the day, high threat score
  act 6  web probes, one exploit answered 200      → alert EXPLOIT 2XX
  act 7  (live) a traffic spike                    → alert BURST
  act 8  (live) a brute force that gets in         → alert LOGIN ACCEPTED (critical)

History is written with past timestamps: the backend reads the time from each
line, so hours of baseline exist the moment it starts. Addresses are made up.
With GEO_PROVIDER=ip-api (45 lookups/min) the ~130 addresses take about three
minutes to appear; with GEO_PROVIDER=mmdb it is instant.
"""
import argparse
import random
import time
from datetime import datetime, timedelta
from pathlib import Path

rng = random.Random(42)
POOL = ["ubuntu", "oracle", "postgres", "git", "pi", "ftp", "mysql", "www", "deploy",
        "jenkins", "hadoop", "es", "minecraft", "steam", "nagios"]
# First octets that are plain public unicast space
OCTETS = [5, 23, 31, 37, 45, 46, 51, 62, 77, 78, 80, 85, 89, 91, 94, 103, 109, 116, 121,
          134, 138, 141, 146, 152, 159, 163, 176, 178, 185, 188, 193, 194, 195, 211, 212, 218]
CHROME = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
PROBES = ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/actuator/env",
          "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/cgi-bin/.%2e/.%2e/bin/sh"]


def rip() -> str:
    return f"{rng.choice(OCTETS)}.{rng.randint(1, 250)}.{rng.randint(1, 250)}.{rng.randint(2, 250)}"


def now() -> datetime:
    return datetime.now().astimezone().replace(microsecond=0)


def failed(ip: str, user: str, at: datetime, invalid: bool = True) -> tuple[datetime, str]:
    kind = "invalid user " if invalid else ""
    return at, (f"{at.isoformat()} vps sshd[{rng.randint(1000, 9999)}]: Failed password for "
                f"{kind}{user} from {ip} port {rng.randint(20000, 60000)} ssh2")


def request(ip: str, path: str, status: int, at: datetime, ua: str = "zgrab/0.x") -> tuple[datetime, str]:
    stamp = at.strftime("%d/%b/%Y:%H:%M:%S %z")
    return at, f'{ip} - - [{stamp}] "GET {path} HTTP/1.1" {status} 512 "-" "{ua}"'


def history(start: datetime) -> tuple[list, list, list[str]]:
    ssh, web = [], []
    crowd = [rip() for _ in range(70)]

    # act 1 — background: everyone tries root/admin, each with its own list
    for ip in crowd:
        for visit in range(rng.randint(2, 5)):
            at = start - timedelta(minutes=rng.uniform(8, 290))
            users = ["root", "admin"] + rng.sample(POOL, rng.randint(0, 4))
            rng.shuffle(users)
            for j, user in enumerate(users):
                for k in range(rng.randint(1, 3)):
                    ssh.append(failed(ip, user, at + timedelta(seconds=4 * j + k), user != "root"))
    # act 2 — same default wordlist, unrelated machines, spread over hours
    for i in range(12):
        ip, at = rip(), start - timedelta(minutes=23 * i + 9)
        for j, user in enumerate(["root", "admin", "user", "test", "ubuntu", "guest"]):
            ssh.append(failed(ip, user, at + timedelta(seconds=3 * j)))
    # act 3 — a botnet arriving together from one /24 with a wordlist nobody else uses
    for i in range(14):
        at = start - timedelta(minutes=24) + timedelta(seconds=75 * i)
        for j, user in enumerate(["zx_miner", "oracle19", "svc_k8s", "deploy77", "root", "sol", "validator"]):
            for k in range(2):
                ssh.append(failed(f"45.9.10.{i + 3}", user, at + timedelta(seconds=2 * j + k)))
    # act 4 — distributed spray on one service account (baseline: one visitor per slot)
    slot = start.replace(minute=start.minute // 10 * 10, second=0) - timedelta(minutes=10)
    for b in range(1, 20):
        ssh.append(failed(rng.choice(crowd), "svc_backup", slot - timedelta(minutes=10 * b) + timedelta(seconds=30)))
    for i in range(11):
        ssh.append(failed(rip(), "svc_backup", slot + timedelta(seconds=25 * i + 5)))
    # act 5 — one address working through a user×password list
    for i in range(700):
        ssh.append(failed("193.32.162.70", f"{POOL[i % len(POOL)]}{i % 9}", start - timedelta(seconds=560 - i * 0.75)))
    # act 6 — web scanners; one exploit path is answered 200
    for _ in range(160):
        web.append(request(rng.choice(crowd), rng.choice(PROBES), 404, start - timedelta(minutes=rng.uniform(1, 290))))
    web.append(request("185.220.101.34", PROBES[5], 200, start - timedelta(seconds=90)))
    for _ in range(40):
        web.append(request(rip(), rng.choice(["/", "/proyectos", "/about"]), 200,
                           start - timedelta(minutes=rng.uniform(1, 290)), CHROME))
    return ssh, web, crowd


def append(path: Path, rows: list) -> None:
    with path.open("a") as f:
        for _, line in sorted(rows):
            f.write(line + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ssh", default="logs/auth.log")
    ap.add_argument("--nginx", default="logs/access.log")
    ap.add_argument("--no-live", action="store_true", help="write the history and stop")
    ap.add_argument("--wait", type=int, default=200,
                    help="seconds of quiet before the live acts (time for geolocation to catch up)")
    args = ap.parse_args()
    ssh_log, web_log = Path(args.ssh), Path(args.nginx)
    for p in (ssh_log, web_log):
        p.parent.mkdir(parents=True, exist_ok=True)
        p.touch()

    ssh, web, crowd = history(now())
    append(ssh_log, ssh)
    append(web_log, web)
    print(f"history: {len(ssh)} SSH lines, {len(web)} HTTP lines")
    if args.no_live:
        return

    print(f"live: background for {args.wait}s, then the spike and the accepted login (Ctrl+C to stop)")
    started = time.time()
    staged = False
    try:
        while True:
            elapsed = time.time() - started
            rows = [failed(rng.choice(crowd), rng.choice(["root", "admin"] + POOL), now())
                    for _ in range(rng.randint(0, 2))]
            if not staged and elapsed >= args.wait:
                staged = True
                # act 7 — spike: the addresses are already known (no geo delay)
                rows += [failed(rng.choice(crowd), rng.choice(["root", "admin"] + POOL), now())
                         for _ in range(500)]
                # act 8 — seven failures, then the password is right
                rows += [failed("62.233.50.245", "deploy", now(), invalid=False) for _ in range(7)]
                at = now()
                rows.append((at, f"{at.isoformat()} vps sshd[4242]: Accepted password for deploy "
                                 "from 62.233.50.245 port 50022 ssh2"))
                print("  staged: traffic spike + accepted login after failures")
            append(ssh_log, rows)
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
