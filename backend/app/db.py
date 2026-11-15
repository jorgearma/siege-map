"""
SQLite persistence.

Two kinds of data, with different lifetimes:

  daily   (day, dim, key) -> count     kept forever. Only aggregates: "root was
                                       tried 812 times on 2026-11-15". This is
                                       what makes monthly / all-time rankings
                                       possible.
  events  one row per event            kept EVENT_RETENTION_DAYS. Feeds the
                                       time-lapse, the sankey and refills the
                                       in-memory store after a restart.
  ips / ip_users                       one row per address: first/last seen,
                                       active days, usernames in the order
                                       they were tried (campaign fingerprint).

HTTP visitor IPs reach this module already truncated (anonymize.py), so no
full visitor address is ever written to disk.

Writes are buffered in memory and flushed in one transaction every few
seconds from a worker thread, so the ingest loop never waits on the disk.
"""
import hashlib
import json
import logging
import os
import sqlite3
import threading
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Iterable, Optional

from .anonymize import mask_ip
from .config import settings
from .models import GeoInfo, SSHEvent

logger = logging.getLogger(__name__)

MAX_USERS_PER_IP = 300

SCHEMA = """
CREATE TABLE IF NOT EXISTS daily (
    day   TEXT NOT NULL,
    dim   TEXT NOT NULL,
    key   TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, dim, key)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS daily_dim ON daily (dim, day);

CREATE TABLE IF NOT EXISTS events (
    id         TEXT PRIMARY KEY,
    ts         TEXT NOT NULL,
    ip         TEXT NOT NULL,
    source     TEXT NOT NULL,
    event_type TEXT NOT NULL,
    username   TEXT NOT NULL,
    status     INTEGER NOT NULL DEFAULT 0,
    count      INTEGER NOT NULL DEFAULT 1,
    attempts   INTEGER NOT NULL DEFAULT 0,
    geo        TEXT,
    meta       TEXT
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);

CREATE TABLE IF NOT EXISTS ips (
    ip           TEXT PRIMARY KEY,
    ip_masked    TEXT NOT NULL,
    source       TEXT NOT NULL,          -- ssh | http
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    last_day     TEXT NOT NULL,
    days_active  INTEGER NOT NULL DEFAULT 1,
    lines        INTEGER NOT NULL DEFAULT 0,
    attempts     INTEGER NOT NULL DEFAULT 0,
    country      TEXT, country_code TEXT, org TEXT,
    net_type     TEXT, cloud TEXT, tags TEXT,
    user_count   INTEGER NOT NULL DEFAULT 0,
    fingerprint  TEXT,
    fp_users     TEXT
);
CREATE INDEX IF NOT EXISTS ips_fp ON ips (fingerprint);
CREATE INDEX IF NOT EXISTS ips_masked ON ips (ip_masked);

CREATE TABLE IF NOT EXISTS ip_users (
    ip       TEXT NOT NULL,
    username TEXT NOT NULL,
    seq      INTEGER NOT NULL,
    count    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ip, username)
) WITHOUT ROWID;
"""


def _day(ts: str) -> str:
    return ts[:10]


def campaign_fingerprint(usernames: list[str]) -> str:
    """Stable id of a wordlist prefix: same first usernames in the same order."""
    return hashlib.sha1("\x1f".join(usernames).encode()).hexdigest()[:10]


class Database:
    def __init__(self, path: Optional[str] = None, prefix_len: Optional[int] = None):
        self.path = path if path is not None else settings.DB_PATH
        self.prefix_len = prefix_len or settings.CAMPAIGN_PREFIX_LEN
        self.persistent = False
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None

        # ── write buffers ──
        self._counters: Counter = Counter()            # (day, dim, key) -> n
        self._dirty_events: dict[str, SSHEvent] = {}
        self._ip_updates: dict[str, dict] = {}
        self._user_updates: dict[str, dict[str, int]] = defaultdict(dict)  # ip -> {user: n}
        self._last_prune = ""

        self._connect()

    # ── connection ────────────────────────────────────────────

    def _connect(self) -> None:
        target = self.path
        if target != ":memory:":
            try:
                folder = os.path.dirname(target)
                if folder:
                    os.makedirs(folder, exist_ok=True)
                self._conn = sqlite3.connect(target, check_same_thread=False)
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("PRAGMA synchronous=NORMAL")
                self.persistent = True
            except (OSError, sqlite3.Error) as e:
                logger.warning(
                    f"Cannot open DB at {target} ({e}) — using an in-memory DB, "
                    "history will NOT survive a restart"
                )
                self._conn = None
        if self._conn is None:
            self._conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self.flush()
        with self._lock:
            self._conn.close()

    # ── write side (buffered) ─────────────────────────────────

    def bump(self, day: str, dim: str, key: str, n: int = 1) -> None:
        if not key or not n:
            return
        with self._lock:
            self._counters[(day, dim, str(key)[:200])] += n

    def bump_many(self, day: str, deltas: Iterable[tuple[str, str, int]]) -> None:
        with self._lock:
            for dim, key, n in deltas:
                if key and n:
                    self._counters[(day, dim, str(key)[:200])] += n

    def save_event(self, event: SSHEvent) -> None:
        """Insert or update (merged duplicates bump count/attempts)."""
        with self._lock:
            self._dirty_events[event.id] = event

    def touch_ip(self, event: SSHEvent, lines: int = 1, attempts: int = 0,
                 tags: Optional[list[str]] = None) -> None:
        geo = event.geo or GeoInfo()
        with self._lock:
            u = self._ip_updates.get(event.ip)
            if u is None:
                u = self._ip_updates[event.ip] = {
                    "source": event.source, "first": event.timestamp,
                    "lines": 0, "attempts": 0, "days": set(),
                }
            u["last"] = event.timestamp
            u["first"] = min(u["first"], event.timestamp)
            u["lines"] += lines
            u["attempts"] += attempts
            u["days"].add(_day(event.timestamp))
            u["geo"] = geo
            if tags is not None:
                u["tags"] = ",".join(tags)
            if event.source == "ssh" and attempts and event.username != "(none)":
                users = self._user_updates[event.ip]
                users[event.username] = users.get(event.username, 0) + attempts

    def flush(self) -> None:
        """Write everything buffered in one transaction."""
        with self._lock:
            counters, self._counters = self._counters, Counter()
            events, self._dirty_events = self._dirty_events, {}
            ip_updates, self._ip_updates = self._ip_updates, {}
            user_updates, self._user_updates = self._user_updates, defaultdict(dict)
            if not (counters or events or ip_updates):
                return
            try:
                cur = self._conn.cursor()
                self._flush_ips(cur, ip_updates, user_updates, counters)
                cur.executemany(
                    "INSERT INTO daily (day, dim, key, count) VALUES (?,?,?,?) "
                    "ON CONFLICT(day, dim, key) DO UPDATE SET count = count + excluded.count",
                    [(d, dim, k, n) for (d, dim, k), n in counters.items() if n],
                )
                cur.executemany(
                    "INSERT OR REPLACE INTO events "
                    "(id, ts, ip, source, event_type, username, status, count, attempts, geo, meta) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    [self._event_row(e) for e in events.values()],
                )
                self._prune(cur)
                self._conn.commit()
            except sqlite3.Error as e:
                self._conn.rollback()
                logger.error(f"DB flush failed, {len(events)} events / {len(counters)} counters lost: {e}")

    @staticmethod
    def _event_row(e: SSHEvent) -> tuple:
        g = e.geo
        geo = json.dumps([g.country, g.country_code, g.city, g.lat, g.lon, g.asn, g.org,
                          g.net_type, g.cloud]) if g else None
        return (e.id, e.timestamp, e.ip, e.source, e.event_type, e.username,
                e.http_status, e.count, e.attempts, geo,
                json.dumps(e.meta) if e.meta else None)

    def _flush_ips(self, cur, ip_updates: dict, user_updates: dict, counters: Counter) -> None:
        for ip, u in ip_updates.items():
            geo: GeoInfo = u["geo"]
            days = sorted(u["days"])
            row = cur.execute(
                "SELECT last_day, days_active FROM ips WHERE ip = ?", (ip,)
            ).fetchone()
            src = u["source"]
            if row is None:
                # First time ever: new on its first day, "returning" on any other
                counters[(days[0], "ip_new", src)] += 1
                for d in days:
                    counters[(d, "ip_unique", src)] += 1
                for d in days[1:]:
                    counters[(d, "ip_returning", src)] += 1
                cur.execute(
                    "INSERT INTO ips (ip, ip_masked, source, first_seen, last_seen, last_day, "
                    "days_active, lines, attempts, country, country_code, org, net_type, cloud, tags) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (ip, ip if "xxx" in ip else mask_ip(ip), src, u["first"], u["last"],
                     days[-1], len(days), u["lines"], u["attempts"], geo.country,
                     geo.country_code, geo.org or geo.asn, geo.net_type, geo.cloud,
                     u.get("tags", "")),
                )
            else:
                new_days = [d for d in days if d > row["last_day"]]
                for d in new_days:
                    counters[(d, "ip_unique", src)] += 1
                    counters[(d, "ip_returning", src)] += 1
                cur.execute(
                    "UPDATE ips SET last_seen = max(last_seen, ?), last_day = max(last_day, ?), "
                    "days_active = days_active + ?, lines = lines + ?, attempts = attempts + ?, "
                    "country = ?, country_code = ?, org = ?, net_type = ?, cloud = ?, "
                    "tags = CASE WHEN ? != '' THEN ? ELSE tags END WHERE ip = ?",
                    (u["last"], days[-1], len(new_days), u["lines"], u["attempts"],
                     geo.country, geo.country_code, geo.org or geo.asn, geo.net_type,
                     geo.cloud, u.get("tags", ""), u.get("tags", ""), ip),
                )

        for ip, users in user_updates.items():
            known = cur.execute(
                "SELECT count(*) AS n, max(seq) AS m FROM ip_users WHERE ip = ?", (ip,)
            ).fetchone()
            n_known = known["n"]
            seq = (known["m"] if known["m"] is not None else -1) + 1
            for username, n in users.items():   # dict keeps first-seen order
                exists = cur.execute(
                    "UPDATE ip_users SET count = count + ? WHERE ip = ? AND username = ?",
                    (n, ip, username),
                ).rowcount
                if not exists and n_known < MAX_USERS_PER_IP:
                    cur.execute(
                        "INSERT INTO ip_users (ip, username, seq, count) VALUES (?,?,?,?)",
                        (ip, username, seq, n),
                    )
                    seq += 1
                    n_known += 1
            cur.execute("UPDATE ips SET user_count = ? WHERE ip = ?", (n_known, ip))
            # Fingerprint once the IP has tried enough different usernames
            if n_known >= self.prefix_len:
                has_fp = cur.execute(
                    "SELECT fingerprint FROM ips WHERE ip = ?", (ip,)
                ).fetchone()
                if has_fp and not has_fp["fingerprint"]:
                    prefix = [r["username"] for r in cur.execute(
                        "SELECT username FROM ip_users WHERE ip = ? ORDER BY seq LIMIT ?",
                        (ip, self.prefix_len),
                    )]
                    cur.execute(
                        "UPDATE ips SET fingerprint = ?, fp_users = ? WHERE ip = ?",
                        (campaign_fingerprint(prefix), ", ".join(prefix), ip),
                    )

    def _prune(self, cur) -> None:
        today = datetime.now().strftime("%Y-%m-%d")
        if self._last_prune == today:
            return
        self._last_prune = today
        cutoff = (datetime.now() - timedelta(days=settings.EVENT_RETENTION_DAYS)).isoformat()
        cur.execute("DELETE FROM events WHERE ts < ?", (cutoff,))

    # ── read side ─────────────────────────────────────────────

    def _q(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    @staticmethod
    def _since(days: Optional[int]) -> str:
        """First day included. days=1 → today, 7 → last 7 days, None → everything."""
        if not days:
            return "0000-00-00"
        return (datetime.now() - timedelta(days=days - 1)).strftime("%Y-%m-%d")

    def top(self, dim: str, days: Optional[int] = None, limit: int = 20) -> list[dict]:
        rows = self._q(
            "SELECT key, sum(count) AS n FROM daily WHERE dim = ? AND day >= ? "
            "GROUP BY key HAVING n > 0 ORDER BY n DESC, key LIMIT ?",
            (dim, self._since(days), limit),
        )
        return [{"key": r["key"], "count": r["n"]} for r in rows]

    def total(self, dim: str, days: Optional[int] = None, key: Optional[str] = None) -> int:
        sql = "SELECT coalesce(sum(count), 0) AS n FROM daily WHERE dim = ? AND day >= ?"
        params: tuple = (dim, self._since(days))
        if key is not None:
            sql += " AND key = ?"
            params += (key,)
        return self._q(sql, params)[0]["n"]

    def distinct_keys(self, dim: str, days: Optional[int] = None) -> int:
        return self._q(
            "SELECT count(DISTINCT key) AS n FROM daily WHERE dim = ? AND day >= ? AND count > 0",
            (dim, self._since(days)),
        )[0]["n"]

    def daily_series(self, dim: str, days: int = 30) -> list[dict]:
        """[{day, <key>: count, ...}] with every day present (zeros included)."""
        rows = self._q(
            "SELECT day, key, count FROM daily WHERE dim = ? AND day >= ? ORDER BY day",
            (dim, self._since(days)),
        )
        by_day: dict[str, dict] = {}
        start = datetime.now() - timedelta(days=days - 1)
        for i in range(days):
            d = (start + timedelta(days=i)).strftime("%Y-%m-%d")
            by_day[d] = {"day": d}
        for r in rows:
            if r["day"] in by_day:
                by_day[r["day"]][r["key"]] = r["count"]
        return list(by_day.values())

    def first_day(self) -> str:
        r = self._q("SELECT min(day) AS d FROM daily")
        return r[0]["d"] or ""

    def heatmap(self, days: Optional[int] = None) -> list[list[int]]:
        grid = [[0] * 24 for _ in range(7)]
        for r in self.top("hour", days, limit=200):
            try:
                dow, hour = (int(x) for x in r["key"].split(":"))
                grid[dow][hour] = r["count"]
            except (ValueError, IndexError):
                pass
        return grid

    # ── attackers ─────────────────────────────────────────────

    def ip_info(self, ip: str) -> Optional[dict]:
        rows = self._q("SELECT * FROM ips WHERE ip = ?", (ip,))
        if not rows:
            return None
        info = dict(rows[0])
        info["tags"] = [t for t in (info.get("tags") or "").split(",") if t]
        info["usernames"] = [
            {"username": r["username"], "count": r["count"]}
            for r in self._q(
                "SELECT username, count FROM ip_users WHERE ip = ? ORDER BY seq LIMIT 100", (ip,)
            )
        ]
        info["campaign_size"] = 0
        if info.get("fingerprint"):
            info["campaign_size"] = self._q(
                "SELECT count(*) AS n FROM ips WHERE fingerprint = ?", (info["fingerprint"],)
            )[0]["n"]
        return info

    def campaigns(self, limit: int = 20, min_ips: int = 2) -> list[dict]:
        rows = self._q(
            "SELECT fingerprint, fp_users, count(*) AS ips, sum(attempts) AS attempts, "
            "min(first_seen) AS first_seen, max(last_seen) AS last_seen, "
            "count(DISTINCT country_code) AS countries, count(DISTINCT org) AS networks "
            "FROM ips WHERE fingerprint IS NOT NULL AND fingerprint != '' "
            "GROUP BY fingerprint HAVING ips >= ? ORDER BY ips DESC, attempts DESC LIMIT ?",
            (min_ips, limit),
        )
        out = []
        for r in rows:
            c = dict(r)
            c["usernames"] = (c.pop("fp_users") or "").split(", ")
            c["top_countries"] = [
                {"country_code": x["country_code"], "ips": x["n"]}
                for x in self._q(
                    "SELECT country_code, count(*) AS n FROM ips WHERE fingerprint = ? "
                    "GROUP BY country_code ORDER BY n DESC LIMIT 5", (c["fingerprint"],)
                )
            ]
            c["sample_ips"] = [
                x["ip"] for x in self._q(
                    "SELECT ip FROM ips WHERE fingerprint = ? ORDER BY attempts DESC LIMIT 5",
                    (c["fingerprint"],)
                )
            ]
            out.append(c)
        return out

    def persistent_ips(self, limit: int = 15) -> list[dict]:
        rows = self._q(
            "SELECT ip, days_active, attempts, lines, first_seen, last_seen, country, "
            "country_code, org, net_type, cloud, tags, user_count FROM ips "
            "WHERE source = 'ssh' ORDER BY days_active DESC, attempts DESC, lines DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in rows]

    def dual_vector(self, limit: int = 15) -> list[dict]:
        """
        Networks seen on BOTH SSH and HTTP. HTTP addresses are stored
        truncated, so the match is by /24 (IPv4) or /48 (IPv6), not by host.
        """
        rows = self._q(
            "SELECT h.ip AS network, count(*) AS ssh_ips, sum(s.attempts) AS ssh_attempts, "
            "h.lines AS http_hits, s.country AS country, s.country_code AS country_code, "
            "s.org AS org FROM ips s JOIN ips h ON h.ip = s.ip_masked "
            "WHERE s.source = 'ssh' AND h.source = 'http' "
            "GROUP BY h.ip ORDER BY ssh_attempts DESC, http_hits DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in rows]

    def ip_counts(self) -> dict:
        r = self._q(
            "SELECT count(*) AS total, "
            "sum(CASE WHEN source = 'ssh' THEN 1 ELSE 0 END) AS ssh, "
            "sum(CASE WHEN days_active > 1 THEN 1 ELSE 0 END) AS came_back, "
            "sum(CASE WHEN fingerprint IS NOT NULL AND fingerprint != '' THEN 1 ELSE 0 END) AS fingerprinted "
            "FROM ips"
        )[0]
        return {k: r[k] or 0 for k in r.keys()}

    # ── event-level queries (retention window) ────────────────

    def load_recent_events(self, limit: int) -> list[SSHEvent]:
        rows = self._q("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,))
        out = []
        for r in reversed(rows):
            geo = None
            if r["geo"]:
                try:
                    g = json.loads(r["geo"])
                    geo = GeoInfo(*g)
                except (ValueError, TypeError):
                    geo = None
            out.append(SSHEvent(
                timestamp=r["ts"], ip=r["ip"], username=r["username"],
                event_type=r["event_type"], raw_line="", id=r["id"], geo=geo,
                source=r["source"], http_status=r["status"], count=r["count"],
                attempts=r["attempts"], meta=json.loads(r["meta"]) if r["meta"] else {},
            ))
        return out

    def bot_of_the_day(self) -> Optional[dict]:
        today = datetime.now().strftime("%Y-%m-%d")
        rows = self._q(
            "SELECT ip, sum(attempts) AS attempts, sum(count) AS lines, "
            "count(DISTINCT username) AS usernames, min(ts) AS first, max(ts) AS last "
            "FROM events WHERE source = 'ssh' AND ts >= ? "
            "GROUP BY ip ORDER BY attempts DESC, lines DESC LIMIT 1",
            (today,),
        )
        if not rows or not rows[0]["ip"]:
            return None
        bot = dict(rows[0])
        info = self.ip_info(bot["ip"]) or {}
        for k in ("country", "country_code", "org", "net_type", "cloud", "tags",
                  "days_active", "fingerprint", "campaign_size"):
            bot[k] = info.get(k)
        bot["top_usernames"] = [u["username"] for u in info.get("usernames", [])[:8]]
        return bot

    def sankey(self, hours: int = 24, top: int = 8) -> dict:
        """country → network → username flows of SSH attempts."""
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        rows = self._q(
            "SELECT geo, username, sum(CASE WHEN attempts > 0 THEN attempts ELSE count END) AS n "
            "FROM events WHERE source = 'ssh' AND ts >= ? AND username != '(none)' "
            "GROUP BY geo, username",
            (cutoff,),
        )
        triples = []
        countries, orgs, users = Counter(), Counter(), Counter()
        for r in rows:
            try:
                g = json.loads(r["geo"]) if r["geo"] else None
            except ValueError:
                g = None
            country = (g[0] if g else None) or "Unknown"
            org = (g[6] or g[5] if g else None) or "Unknown network"
            triples.append((country, org, r["username"], r["n"]))
            countries[country] += r["n"]
            orgs[org] += r["n"]
            users[r["username"]] += r["n"]

        keep_c = {k for k, _ in countries.most_common(top)}
        keep_o = {k for k, _ in orgs.most_common(top)}
        keep_u = {k for k, _ in users.most_common(top + 2)}
        left, right = Counter(), Counter()
        for country, org, user, n in triples:
            c = country if country in keep_c else "Other countries"
            o = org if org in keep_o else "Other networks"
            u = user if user in keep_u else "other users"
            left[(c, o)] += n
            right[(o, u)] += n

        names: list[str] = []
        index: dict[tuple[int, str], int] = {}

        def node(layer: int, name: str) -> int:
            if (layer, name) not in index:
                index[(layer, name)] = len(names)
                names.append(name)
            return index[(layer, name)]

        links = [{"source": node(0, c), "target": node(1, o), "value": n}
                 for (c, o), n in left.most_common()]
        links += [{"source": node(1, o), "target": node(2, u), "value": n}
                  for (o, u), n in right.most_common()]
        layers = {i: layer for (layer, _), i in index.items()}
        return {
            "nodes": [{"name": n[:28], "layer": layers[i]} for i, n in enumerate(names)],
            "links": links,
        }

    def replay(self, hours: int = 24, buckets: int = 240, per_bucket: int = 30) -> dict:
        """Down-sampled history for the time-lapse: one frame per bucket."""
        end = datetime.now()
        start = end - timedelta(hours=hours)
        rows = self._q(
            "SELECT ts, source, event_type, geo, count FROM events "
            "WHERE ts >= ? AND geo IS NOT NULL ORDER BY ts",
            (start.isoformat(),),
        )
        span = (end - start).total_seconds() / buckets
        frames: list[dict] = [dict() for _ in range(buckets)]
        totals = [0] * buckets
        for r in rows:
            try:
                t = datetime.fromisoformat(r["ts"])
                g = json.loads(r["geo"])
            except (ValueError, TypeError):
                continue
            lat, lon = g[3], g[4]
            if not lat and not lon:
                continue
            i = min(buckets - 1, max(0, int((t - start).total_seconds() // span)))
            kind = ("ssh" if r["source"] == "ssh"
                    else "visit" if r["event_type"].startswith("visit_") else "http")
            key = (round(lat, 1), round(lon, 1), kind)
            totals[i] += r["count"]
            cell = frames[i].get(key)
            if cell:
                cell[4] += r["count"]
            elif len(frames[i]) < per_bucket:
                frames[i][key] = [round(lat, 2), round(lon, 2), kind, g[1], r["count"]]
        return {
            "start": start.isoformat(timespec="seconds"),
            "end": end.isoformat(timespec="seconds"),
            "bucket_seconds": span,
            "frames": [list(f.values()) for f in frames],
            "totals": totals,
        }

    def stats(self) -> dict:
        r = self._q(
            "SELECT (SELECT count(*) FROM events) AS events, "
            "(SELECT count(*) FROM ips) AS ips, (SELECT count(*) FROM daily) AS daily_rows"
        )[0]
        return {"persistent": self.persistent, "path": self.path if self.persistent else ":memory:",
                **{k: r[k] for k in r.keys()}}


db = Database()
