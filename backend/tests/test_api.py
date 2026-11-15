"""HTTP surface: input validation and what leaves through the exports."""
import csv
import io
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from app import intel, main
from app.models import GeoInfo, SSHEvent

NOW = datetime.now().replace(microsecond=0)
GEO = GeoInfo("Germany", "DE", "Berlin", 52.5, 13.4, "AS1 Hetzner", "Hetzner", "hosting", "Hetzner")


@pytest.fixture
def client(monkeypatch):
    main.store.events.clear()
    main.store._by_ip.clear()
    main.store._seen.clear()
    calls = []

    async def fake_greynoise(ip):
        calls.append(ip)
        return {}

    monkeypatch.setattr(intel, "check_greynoise", fake_greynoise)
    c = TestClient(main.app)          # no lifespan: nothing is tailed
    c.greynoise_calls = calls
    return c


def event(ip="8.8.8.8", user="root", n=[0], **kw):
    n[0] += 1
    e = SSHEvent(timestamp=NOW.isoformat(), ip=ip, username=user, event_type="failed_password",
                 raw_line="", id=f"t{n[0]}", geo=GEO, attempts=1, **kw)
    main.store.add(e)
    main.db.touch_ip(e, lines=1, attempts=1)
    return e


@pytest.mark.parametrize("bad", [
    "not-an-ip", "8.8.8.8%3Fkey=1", "8.8.8.8%20", "1.2.3", "8.8.8.8;id", "a" * 60,
    "..%2F..%2Fv3%2Fnoise", "1.2.3.4.xxx",
])
def test_attacker_endpoint_rejects_anything_but_an_address(client, bad):
    assert client.get(f"/api/attacker/{bad}").status_code in (400, 404)
    assert client.greynoise_calls == []


def test_unknown_address_never_reaches_the_external_api(client):
    """The quota cannot be burned with made-up addresses."""
    for i in range(50):
        assert client.get(f"/api/attacker/9.9.9.{i}").status_code == 404
    assert client.greynoise_calls == []


def test_known_address_profile(client):
    for u in ("root", "admin", "test"):
        event(ip="8.8.4.4", user=u)
    main.db.flush()
    body = client.get("/api/attacker/8.8.4.4").json()
    assert body["unique_usernames"] == 3 and body["attack_pattern"] == "PASSWORD_GUESSING"
    assert body["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert sum(p["max"] for p in body["score_breakdown"]) == 100
    assert body["narrative"][0]["kind"] == "contact" and body["narrative"][-1]["kind"] == "verdict"
    assert client.greynoise_calls == ["8.8.4.4"]


def test_masked_http_address_is_accepted_but_not_sent_out(client):
    e = SSHEvent(timestamp=NOW.isoformat(), ip="83.45.120.xxx", username="/.env",
                 event_type="http_probe", raw_line="", id="m1", geo=GEO, source="http",
                 http_status=404)
    main.store.add(e)
    body = client.get("/api/attacker/83.45.120.xxx").json()
    assert body["attack_pattern"] == "WEB_SCANNING"
    assert client.greynoise_calls == []


def test_csv_neutralises_formulas_and_keeps_its_columns(client):
    nasty = ["=cmd|'/c calc'!A1", "+1+1", "-2", "@SUM(A1)", 'a,b"c', "plain"]
    for i, user in enumerate(nasty):
        event(ip=f"8.8.1.{i + 1}", user=user)
    res = client.get("/api/export/csv")
    assert res.status_code == 200
    rows = list(csv.reader(io.StringIO(res.text)))
    header, data = rows[0], rows[1:]
    assert all(len(r) == len(header) for r in data)            # commas/quotes did not shift cells
    users = [r[header.index("username")] for r in data]
    assert users == ["'=cmd|'/c calc'!A1", "'+1+1", "'-2", "'@SUM(A1)", 'a,b"c', "plain"]
    assert not any(cell.startswith(("=", "+", "-", "@")) for r in data for cell in r)


def test_blocklist_only_lists_repeat_offenders(client):
    for _ in range(12):
        event(ip="8.8.2.2", user="root")
    event(ip="8.8.2.3", user="root")
    main.db.flush()
    txt = client.get("/api/export/blocklist?min_attempts=10").text
    lines = [line for line in txt.splitlines() if not line.startswith("#")]
    assert "8.8.2.2" in lines and "8.8.2.3" not in lines
    nft = client.get("/api/export/blocklist?min_attempts=10&format=nft").text
    assert "add element inet filter siege4 {" in nft and "8.8.2.2" in nft


def test_alerts_endpoint_shape(client):
    body = client.get("/api/alerts").json()
    assert set(body) == {"enabled", "notifications", "active", "history", "today"}
    assert client.get("/api/alerts?severity=nope").status_code == 422


def test_stix_pattern_for_truncated_addresses():
    from app.stix_export import stix_pattern
    assert stix_pattern("1.2.3.4") == "[ipv4-addr:value = '1.2.3.4']"
    assert stix_pattern("1.2.3.xxx") == "[ipv4-addr:value ISSUBSET '1.2.3.0/24']"
    assert stix_pattern("2a02:1234:5678::xxxx") == "[ipv6-addr:value ISSUBSET '2a02:1234:5678::/48']"
    assert stix_pattern("2001:db8::1").startswith("[ipv6-addr:value")


def test_markdown_report_escapes_attacker_text(client):
    from app.report import esc
    assert esc("a|b`c<script>") == "`a\\|b'c&lt;script&gt;`"
    for _ in range(3):
        event(ip="8.8.3.3", user="x|y<img src=x onerror=alert(1)>`")
    main.db.bump("%s" % NOW.strftime("%Y-%m-%d"), "ssh_user", "x|y<img src=x onerror=alert(1)>`", 3)
    main.db.flush()
    res = client.get("/api/export/report.md?range=all")
    assert res.status_code == 200 and res.text.startswith("# Threat report")
    assert "<img" not in res.text and "x\\|y&lt;img" in res.text


def test_mitre_summary_counts_addresses_per_technique(client):
    for u in ("root", "admin", "test"):
        event(ip="8.8.5.5", user=u)
    for i in range(8):
        event(ip="8.8.5.6", user=f"user{i}")
    body = client.get("/api/stats/mitre").json()["techniques"]
    by_id = {t["id"]: t for t in body}
    assert by_id["T1110.001"]["count"] == 1 and by_id["T1110.003"]["count"] == 1
    assert by_id["T1110.003"]["name"] == "Password Spraying"
    assert all(t["tactic"] for t in body)


def test_hud_reports_todays_records(client):
    main._hud_cache = ({}, 0.0)
    for _ in range(3):
        event(ip="8.8.4.4")
    event(ip="8.8.8.8")
    body = client.get("/api/stats/hud").json()
    assert body["today"] == {"events": 4, "unique_ips": 2}
    assert body["records"]["top_ip"] == {"ip": "8.8.4.4", "count": 3, "country_code": "DE"}
    far = body["records"]["farthest"]
    assert far["country_code"] == "DE" and far["km"] == round(
        main._distance_km(main.settings.VPS_LAT, main.settings.VPS_LON, GEO.lat, GEO.lon))
    assert body["records"]["busiest_minute"]["count"] == 4
    assert body["utc_offset_min"] == 0 and body["uptime_seconds"] >= 0
    main._hud_cache = ({}, 0.0)


def test_hud_is_empty_without_events(client):
    main._hud_cache = ({}, 0.0)
    body = client.get("/api/stats/hud").json()
    assert body["today"] == {"events": 0, "unique_ips": 0}
    assert body["records"] == {"farthest": None, "top_ip": None, "busiest_minute": None}
    main._hud_cache = ({}, 0.0)
