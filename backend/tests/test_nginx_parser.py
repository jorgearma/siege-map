import json

from app.nginx_parser import (
    parse_nginx_line, parse_nginx_fields, classify_referrer, primary_language,
)

CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"


def combined(path="/", status=200, ua=CHROME, ref="-", method="GET", ip="8.8.8.8"):
    return f'{ip} - - [15/Nov/2026:10:00:00 +0100] "{method} {path} HTTP/1.1" {status} 512 "{ref}" "{ua}"'


def as_json(**kw):
    base = {"time": "2026-11-15T10:00:00+01:00", "ip": "8.8.8.8", "method": "GET", "uri": "/",
            "status": 200, "ua": CHROME, "referer": "", "lang": "es-ES,es;q=0.9", "host": "example.com"}
    base.update(kw)
    return json.dumps(base)


def test_human_visit_desktop():
    e = parse_nginx_line(combined("/about"))
    assert e.event_type == "visit_desktop"
    assert e.meta["os"] == "Windows" and e.meta["browser"] == "Chrome"
    assert e.meta["visitor"] == "human" and e.meta["ref"] == "direct"


def test_human_visit_mobile_from_linkedin():
    e = parse_nginx_line(combined("/", ua=IPHONE, ref="https://www.linkedin.com/feed/"))
    assert e.event_type == "visit_mobile"
    assert (e.meta["os"], e.meta["browser"], e.meta["ref"]) == ("iOS", "Safari", "linkedin")


def test_static_assets_are_not_events():
    assert parse_nginx_line(combined("/assets/app.js")) is None
    assert parse_nginx_fields(combined("/assets/app.js"))["path"] == "/assets/app.js"


def test_private_ip_skipped():
    assert parse_nginx_line(combined(ip="172.18.0.1")) is None


def test_secret_probe_has_signature():
    e = parse_nginx_line(combined("/.env", status=404, ua="curl/8.0"))
    assert e.event_type == "secret_probe" and e.meta["sig"] == "dotenv-exposure"


def test_cve_probe():
    e = parse_nginx_line(combined("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", status=404))
    assert e.event_type == "exploit_probe" and e.meta["sig"] == "CVE-2017-9841"


def test_query_string_is_used_for_signatures_but_not_shown():
    e = parse_nginx_line(combined("/hello.world?%ADd+allow_url_include%3d1", status=404))
    assert e.meta["sig"] == "CVE-2024-4577" and "?" not in e.username


def test_crawler_and_tool():
    assert parse_nginx_line(combined(ua="Mozilla/5.0 (compatible; Googlebot/2.1)")).meta["visitor"] == "crawler"
    assert parse_nginx_line(combined(ua="python-requests/2.32.0")).meta["visitor"] == "tool"


def test_headless_and_ancient_browsers_are_not_people():
    headless = CHROME.replace("Chrome/131", "HeadlessChrome/131")
    old = CHROME.replace("Chrome/131", "Chrome/74")
    assert parse_nginx_line(combined(ua=headless)).event_type == "fake_browser"
    assert parse_nginx_line(combined(ua=old)).event_type == "fake_browser"


def test_json_format():
    e = parse_nginx_line(as_json(uri="/proyectos?x=1", referer="https://github.com/jorge"))
    assert e.event_type == "visit_desktop" and e.username == "/proyectos"
    assert e.meta["lang"] == "es" and e.meta["ref"] == "github"
    assert e.timestamp == "2026-11-15T09:00:00"  # +01:00 → UTC (test TZ)


def test_json_browser_without_language_is_fake():
    assert parse_nginx_line(as_json(lang="")).event_type == "fake_browser"


def test_json_internal_referrer_uses_host():
    e = parse_nginx_line(as_json(referer="https://example.com/otra"))
    assert e.meta["ref"] == "internal"


def test_garbage():
    assert parse_nginx_line("not a log line") is None
    assert parse_nginx_line("{broken json") is None
    assert parse_nginx_line('{"no_ip": 1}') is None


def test_referrer_keeps_only_the_site():
    assert classify_referrer("https://www.google.com/search?q=secret+query") == "search:google"
    assert classify_referrer("https://blog.example.org/post/42?token=abc") == "blog.example.org"
    assert classify_referrer("-") == "direct"


def test_primary_language():
    assert primary_language("es-ES,es;q=0.9,en;q=0.8") == "es"
    assert primary_language("") == "" and primary_language("*") == ""
