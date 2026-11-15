"""Counting rules end to end: parser → recorder → store → SQLite."""
from datetime import datetime, timedelta

import pytest

from app.attempts import attempt_counter
from app.db import Database, campaign_fingerprint
from app.models import GeoInfo
from app.nginx_parser import parse_nginx_line
from app.parser import parse_line
from app.recorder import mark_attempt, record
from app.store import EventStore
from app.visitors import VisitorTracker, visitor_tracker

NOW = datetime.now().replace(microsecond=0)
GEO = GeoInfo("Germany", "DE", "Berlin", 52.5, 13.4, "AS1 Hetzner", "Hetzner", "hosting", "Hetzner")
CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


@pytest.fixture
def env():
    attempt_counter._state.clear()
    visitor_tracker._seen.clear()
    return Database(":memory:", prefix_len=3), EventStore(max_events=1000)


def ssh(db, store, user, ip="8.8.8.8", kind="Failed password for", at=NOW, n=[0]):
    n[0] += 1
    line = f"{at.isoformat()} vps sshd[1]: {kind} {user} from {ip} port 22 ssh2"
    e = parse_line(line)
    e.id, e.geo = f"e{n[0]}", GEO
    mark_attempt(e)
    record(db, e)
    stored, is_new = store.add(e)
    db.save_event(stored)
    return stored, is_new


def http(db, store, path="/", ip="9.9.9.9", status=200, ua=CHROME, n=[0]):
    n[0] += 1
    ts = NOW.strftime("%d/%b/%Y:%H:%M:%S +0000")
    e = parse_nginx_line(f'{ip} - - [{ts}] "GET {path} HTTP/1.1" {status} 1 "-" "{ua}"')
    e.id, e.geo = f"h{n[0]}", GEO
    full = e.ip
    e.ip = "9.9.9.xxx"
    record(db, e, full_ip=full)
    stored, _ = store.add(e)
    db.save_event(stored)
    return e


def test_brute_force_is_counted_in_full_but_shown_once(env):
    db, store = env
    results = [ssh(db, store, "root", at=NOW + timedelta(seconds=i)) for i in range(10)]
    db.flush()
    same_minute = len({(NOW + timedelta(seconds=i)).isoformat()[:16] for i in range(10)})
    assert sum(is_new for _, is_new in results) == same_minute      # feed: one per minute
    assert db.total("ssh_attempts") == 10                           # counters: all of them
    assert db.top("ssh_user")[0] == {"key": "root", "count": 10}
    assert store.top_usernames()[0]["count"] == 10
    assert store.total_count() == 10


def test_username_ranking_ignores_http_paths(env):
    db, store = env
    ssh(db, store, "admin")
    for _ in range(5):
        http(db, store, "/wp-login.php", status=404)
    db.flush()
    assert [u["username"] for u in store.top_usernames()] == ["admin"]
    assert [u["key"] for u in db.top("ssh_user")] == ["admin"]
    assert db.top("ssh_cat")[0]["key"] == "default"


def test_campaign_groups_ips_with_the_same_wordlist_order(env):
    db, store = env
    for ip in ("8.8.8.8", "8.8.4.4", "1.1.1.1"):
        for i, user in enumerate(["root", "admin", "pi", "oracle"]):
            ssh(db, store, user, ip=ip, at=NOW + timedelta(seconds=i * 10))
    for i, user in enumerate(["pi", "root", "admin"]):               # other order
        ssh(db, store, user, ip="9.9.9.9", at=NOW + timedelta(seconds=i * 10))
    db.flush()
    campaigns = db.campaigns()
    assert len(campaigns) == 1
    assert campaigns[0]["ips"] == 3 and campaigns[0]["usernames"] == ["root", "admin", "pi"]
    assert campaigns[0]["fingerprint"] == campaign_fingerprint(["root", "admin", "pi"])
    assert db.ip_info("9.9.9.9")["campaign_size"] == 1


def test_new_and_returning_ips(env):
    db, store = env
    ssh(db, store, "root", at=NOW - timedelta(days=2))
    db.flush()
    ssh(db, store, "root", at=NOW)
    ssh(db, store, "root", ip="1.1.1.1", at=NOW)
    db.flush()
    assert db.total("ip_new", 1, key="ssh") == 1          # only 1.1.1.1 is new today
    assert db.total("ip_returning", 1, key="ssh") == 1    # 8.8.8.8 came back
    info = db.ip_info("8.8.8.8")
    assert info["days_active"] == 2 and info["attempts"] == 2
    assert db.persistent_ips(1)[0]["ip"] == "8.8.8.8"
    assert db.ip_counts() == {"total": 2, "ssh": 2, "came_back": 1, "fingerprinted": 0}


def test_visitors_are_unique_per_day_and_profiled(env):
    db, store = env
    for path in ("/", "/about", "/proyectos"):
        http(db, store, path)
    db.flush()
    assert db.total("visitor", key="browser") == 1         # 3 pages, 1 person
    assert db.top("device")[0] == {"key": "desktop", "count": 1}
    assert db.top("os")[0]["key"] == "Windows"
    assert db.total("source", key="visit") == 3            # but 3 page views


def test_browser_that_probes_is_reclassified(env):
    db, store = env
    http(db, store, "/")
    http(db, store, "/.env", status=404)
    db.flush()
    assert db.total("visitor", key="browser") == 0
    assert db.total("visitor", key="scanner") == 1
    assert db.top("device") == []                          # not counted as a person
    assert db.top("http_sig")[0]["key"].startswith("dotenv-exposure|")


def test_asset_fetch_verifies_a_browser():
    t = VisitorTracker()
    e = parse_nginx_line(f'9.9.9.9 - - [15/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "{CHROME}"')
    assert ("visitor", "browser", 1) in t.on_event(e, "9.9.9.9")
    assert t.on_asset("9.9.9.9", "2026-11-15") == [("visitor", "browser", -1), ("visitor", "browser_verified", 1)]
    assert t.on_asset("9.9.9.9", "2026-11-15") == []       # only once
    assert t.on_event(e, "9.9.9.9") == []                  # stays verified
    assert t.on_asset("7.7.7.7", "2026-11-15") == []       # unknown address


def test_events_survive_a_restart(env, tmp_path):
    path = str(tmp_path / "siege.db")
    db, store = Database(path), EventStore(max_events=100)
    ssh(db, store, "root")
    http(db, store, "/")
    db.close()

    db2, store2 = Database(path), EventStore(max_events=100)
    assert db2.persistent
    restored = db2.load_recent_events(100)
    store2.restore(restored, total=db2.total("source"))
    assert {e.source for e in restored} == {"ssh", "http"}
    assert restored[0].geo.country == "Germany"
    assert store2.total_count() == 2
    assert store2.top_usernames()[0]["username"] == "root"


def test_unwritable_path_falls_back_to_memory():
    db = Database("/proc/definitely/not/writable/siege.db")
    assert not db.persistent
    db.bump("2026-11-15", "x", "y")
    db.flush()
    assert db.total("x") == 1


def test_replay_sankey_and_bot_of_the_day(env):
    db, store = env
    for i in range(6):
        ssh(db, store, "root", at=NOW - timedelta(minutes=i * 3))
    ssh(db, store, "pi", ip="1.1.1.1")
    db.flush()

    replay = db.replay(hours=1, buckets=30)
    assert len(replay["frames"]) == 30 and sum(replay["totals"]) == 7
    assert any(f and f[0][2] == "ssh" for f in replay["frames"])

    sankey = db.sankey(hours=1)
    names = [n["name"] for n in sankey["nodes"]]
    assert "Germany" in names and "root" in names
    assert all(l["source"] != l["target"] for l in sankey["links"])

    bot = db.bot_of_the_day()
    assert bot["ip"] == "8.8.8.8" and bot["country"] == "Germany"


def test_heatmap_and_series(env):
    db, store = env
    ssh(db, store, "root")
    db.flush()
    grid = db.heatmap()
    assert grid[NOW.weekday()][NOW.hour] == 1 and sum(map(sum, grid)) == 1
    series = db.daily_series("source", 7)
    assert len(series) == 7 and series[-1]["ssh"] == 1
