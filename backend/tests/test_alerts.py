"""Alert rules and — above all — the noise control around them."""
from datetime import datetime, timedelta

import pytest

from app import analyzer as analyzer_module
from app import notify
from app.alerts import AlertEngine
from app.config import settings
from app.models import GeoInfo, SSHEvent
from app.store import EventStore

NOW = datetime.now().replace(microsecond=0)
GEO = GeoInfo("Germany", "DE", "Berlin", 52.5, 13.4, "AS1 Hetzner", "Hetzner", "hosting", "Hetzner")


@pytest.fixture
def env(monkeypatch):
    store = EventStore(max_events=20000)
    monkeypatch.setattr(analyzer_module, "_store", store)
    analyzer_module._profile_cache.clear()
    saved = []
    engine = AlertEngine(store, analyzer_module.analyzer, cooldown=600, persist=saved.append)
    return store, engine, saved


def add(store, ip="8.8.8.8", user="root", at=NOW, kind="failed_password", source="ssh",
        status=0, meta=None, geo=GEO, n=[0]):
    n[0] += 1
    e = SSHEvent(timestamp=at.isoformat(), ip=ip, username=user, event_type=kind, raw_line="",
                 id=f"a{n[0]}", geo=geo, source=source, http_status=status,
                 attempts=1 if source == "ssh" else 0, meta=meta or {})
    store.add(e)
    return e


CAND = {"rule": "high_score", "key": "8.8.8.8", "ip": "8.8.8.8", "severity": "HIGH",
        "title": "t", "detail": "d"}


# ── noise control ─────────────────────────────────────────────

def test_same_condition_is_announced_once(env):
    _, engine, saved = env
    first = engine.raise_alert(dict(CAND), NOW)
    again = [engine.raise_alert(dict(CAND), NOW + timedelta(seconds=30 * i)) for i in range(1, 20)]
    assert first is not None and again == [None] * 19
    assert len(engine.active) == 1
    assert engine.active_alerts()[0]["hits"] == 20
    assert {a["id"] for a in saved} == {first["id"]}       # one row, updated in place


def test_escalation_is_announced_again(env):
    _, engine, _ = env
    engine.raise_alert(dict(CAND), NOW)
    worse = engine.raise_alert({**CAND, "severity": "CRITICAL", "title": "worse"}, NOW)
    assert worse and worse["severity"] == "CRITICAL" and worse["title"] == "worse"
    # ...but going back down is not news
    assert engine.raise_alert(dict(CAND), NOW) is None
    assert engine.active_alerts()[0]["severity"] == "CRITICAL"


def test_cooldown_then_a_new_alert(env):
    _, engine, saved = env
    first = engine.raise_alert(dict(CAND), NOW)
    assert engine.resolve_stale(NOW + timedelta(seconds=599)) == []
    resolved = engine.resolve_stale(NOW + timedelta(seconds=601))
    assert [a["id"] for a in resolved] == [first["id"]] and saved[-1]["status"] == "resolved"
    second = engine.raise_alert(dict(CAND), NOW + timedelta(seconds=700))
    assert second and second["id"] != first["id"]


def test_different_subjects_do_not_hide_each_other(env):
    _, engine, _ = env
    assert engine.raise_alert(dict(CAND), NOW)
    assert engine.raise_alert({**CAND, "key": "9.9.9.9"}, NOW)
    assert engine.raise_alert({**CAND, "rule": "user_spray"}, NOW)
    assert len(engine.active) == 3


# ── rules ─────────────────────────────────────────────────────

def test_accepted_login_after_failures_is_critical(env):
    store, engine, saved = env
    for i in range(5):
        add(store, ip="5.5.5.5", user="deploy", at=NOW - timedelta(seconds=90 * i))
    alert = engine.on_accepted_login("5.5.5.5", "deploy", "password", NOW)
    assert alert["severity"] == "CRITICAL" and "T1078" in alert["mitre"]
    # The account name goes to the operator only: not stored, not public
    assert alert["private"] == "account: deploy"
    assert all("deploy" not in str(v) for v in saved[-1].values())


def test_clean_login_is_ignored(env):
    store, engine, _ = env
    assert engine.on_accepted_login("7.7.7.7", "jorge", "publickey", NOW) is None
    add(store, ip="7.7.7.7", user="jorge")            # one typo is not a brute force
    assert engine.on_accepted_login("7.7.7.7", "jorge", "password", NOW) is None
    assert not engine.active


def test_burst_needs_to_beat_the_baseline(env):
    store, engine, _ = env
    # Two hours of steady background: 60 events every five minutes
    for block in range(1, 25):
        for i in range(60):
            add(store, ip=f"20.0.{block}.{i}", at=NOW - timedelta(minutes=5 * block + 2))
    for i in range(60):                                # the same volume now: nothing
        add(store, ip=f"21.0.0.{i}", at=NOW - timedelta(minutes=1))
    assert engine._rule_burst(NOW) == []
    for i in range(600):                               # ten times the usual
        add(store, ip=f"22.{i // 250}.{i % 250}.1", at=NOW - timedelta(minutes=1))
    burst = engine._rule_burst(NOW)
    assert len(burst) == 1 and burst[0]["severity"] in ("MEDIUM", "HIGH")


def test_burst_without_history_stays_silent(env):
    store, engine, _ = env
    for i in range(500):
        add(store, ip=f"23.{i // 250}.{i % 250}.1", at=NOW - timedelta(minutes=1))
    assert engine._rule_burst(NOW) == []               # no baseline, no claim


def geo(code):
    return GeoInfo(code, code, "x", 0, 0, "AS", "Org", "hosting", "")


def test_country_surge_is_about_one_country(env, monkeypatch):
    store, engine, _ = env
    monkeypatch.setattr(settings, "ALERT_COUNTRY_IPS", 15)
    codes = ["US", "CN", "DE", "BR"]
    for block in range(1, 13):                           # two hours, 3 addresses per country
        for c, code in enumerate(codes):
            for i in range(3):
                add(store, ip=f"30.{block}.{c}.{i + 1}", geo=geo(code),
                    at=NOW - timedelta(minutes=10 * block + 3))
    # Everything grows together → not a country story (the burst rule covers it)
    for c, code in enumerate(codes):
        for i in range(20):
            add(store, ip=f"31.{c}.{i}.1", geo=geo(code), at=NOW - timedelta(minutes=2))
    assert engine._rule_country_surge(NOW) == []
    # Now one country alone floods in
    for i in range(200):
        add(store, ip=f"32.0.{i}.1", geo=geo("CN"), at=NOW - timedelta(minutes=1))
    surge = engine._rule_country_surge(NOW)
    assert [s["key"] for s in surge] == ["CN"]


def test_exploit_answered_2xx(env):
    store, engine, _ = env
    sig = {"sig": "CVE-2017-9841", "sig_name": "PHPUnit RCE", "sig_kind": "exploit"}
    add(store, ip="3.3.3.xxx", user="/vendor/phpunit/eval-stdin.php", source="http",
        kind="http_exploit", status=404, meta=sig)
    assert engine._rule_exploit_2xx() == []            # the normal case: it failed
    add(store, ip="3.3.4.xxx", user="/vendor/phpunit/eval-stdin.php", source="http",
        kind="http_exploit", status=200, meta=sig)
    hit = engine._rule_exploit_2xx()
    assert len(hit) == 1 and hit[0]["severity"] == "HIGH" and hit[0]["mitre"] == ["T1190"]


def test_campaign_rule_only_alerts_on_confident_active_groups(env):
    _, engine, _ = env
    base = {"fingerprint": "abc", "ips": 12, "usernames": ["a", "b"], "label": "x",
            "confidence": 80, "severity": "HIGH", "evidence": [], "kind": "wordlist"}
    assert engine._rule_campaign([{**base, "level": "LOW", "active": True}]) == []
    assert engine._rule_campaign([{**base, "level": "HIGH", "active": False}]) == []
    assert engine._rule_campaign([{**base, "level": "HIGH", "active": True, "ips": 2}]) == []
    assert len(engine._rule_campaign([{**base, "level": "HIGH", "active": True}])) == 1


def test_high_score_and_spray_rules(env, monkeypatch):
    store, engine, _ = env
    monkeypatch.setattr(settings, "ALERT_SCORE_THRESHOLD", 60)
    monkeypatch.setattr(settings, "ALERT_SPRAY_USERS", 40)
    for i in range(400):
        add(store, ip="6.6.6.6", user=f"user{i % 60}", at=NOW - timedelta(seconds=540 - i))
    add(store, ip="6.6.6.7", user="root", at=NOW - timedelta(seconds=30))     # a nobody
    announced = engine.evaluate(now=NOW)
    assert {(a["rule"], a["key"]) for a in announced} == {("high_score", "6.6.6.6"),
                                                         ("user_spray", "6.6.6.6")}
    assert engine.evaluate(now=NOW + timedelta(seconds=30)) == []             # no repeat


# ── delivery ──────────────────────────────────────────────────

ALERT = {"id": "1", "ts": "2026-11-15T10:00:00", "severity": "HIGH", "title": "T",
         "detail": "D", "mitre": ["T1110"], "private": "account: x"}


def test_webhook_payload_shape_per_service():
    assert set(notify.webhook_payload("https://discord.com/api/webhooks/1/abc", ALERT)) == {"content"}
    assert set(notify.webhook_payload("https://hooks.slack.com/services/T/B/x", ALERT)) == {"text"}
    generic = notify.webhook_payload("https://example.org/hook", ALERT)
    assert generic["alert"]["id"] == "1" and "account: x" in generic["text"]


def test_notification_severity_floor(monkeypatch):
    monkeypatch.setattr(settings, "ALERT_NOTIFY_MIN_SEVERITY", "HIGH")
    assert notify.should_notify({"severity": "CRITICAL"}) and notify.should_notify({"severity": "HIGH"})
    assert not notify.should_notify({"severity": "MEDIUM"})
