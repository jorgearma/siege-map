from app.anonymize import mask_ip
from app.geo import cloud_brand, geo_from_mmdb_records, guess_net_type
from app.intel import parse_tor_list
from app.signatures import SIGNATURES, match_signature
from app.ua import parse_ua
from app.usernames import categorize


def test_ua_families():
    ua = parse_ua("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36")
    assert (ua.device, ua.os, ua.browser, ua.automated) == ("mobile", "Android", "Chrome", False)
    ua = parse_ua("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15")
    assert (ua.device, ua.os, ua.browser) == ("desktop", "macOS", "Safari")
    ua = parse_ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0")
    assert ua.browser == "Edge"
    ua = parse_ua("Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1")
    assert (ua.device, ua.os) == ("tablet", "iOS")
    ua = parse_ua("Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0")
    assert (ua.os, ua.browser, ua.automated) == ("Linux", "Firefox", False)


def test_username_categories():
    assert categorize("root") == "default"
    assert categorize("Pi") == "iot"
    assert categorize("postgres") == "service"
    assert categorize("solana") == "crypto"
    assert categorize("deploy") == "devops"
    assert categorize("minecraft") == "gaming"
    assert categorize("test123") == "default"      # digits stripped
    assert categorize("xk9_q") == "other"
    assert categorize("(none)") == "other"


def test_signatures_compile_and_have_unique_meaning():
    assert len(SIGNATURES) > 40
    assert match_signature("/cgi-bin/luci/;stok=/locale?form=country").id == "CVE-2023-1389"
    assert match_signature("/.git/config").id == "git-exposure"
    assert match_signature("/wp-login.php").product == "WordPress"
    assert match_signature("/about") is None and match_signature("") is None


def test_mask_ip():
    assert mask_ip("83.45.120.17") == "83.45.120.xxx"
    assert mask_ip("2a02:1234:5678:9::1") == "2a02:1234:5678::xxxx"


def test_net_type_and_cloud():
    assert cloud_brand("AS14061 DigitalOcean, LLC") == "DigitalOcean"
    assert guess_net_type("Hetzner Online GmbH") == "hosting"
    assert guess_net_type("Telefonica de Espana SAU") == "residential"
    assert guess_net_type("") == "unknown"


def test_mmdb_record_mapping():
    geo = geo_from_mmdb_records(
        {"country": {"iso_code": "DE", "names": {"en": "Germany"}},
         "city": {"names": {"en": "Falkenstein"}},
         "location": {"latitude": 50.47, "longitude": 12.37}},
        {"autonomous_system_number": 24940, "autonomous_system_organization": "Hetzner Online GmbH"},
    )
    assert (geo.country, geo.country_code, geo.city) == ("Germany", "DE", "Falkenstein")
    assert geo.asn == "AS24940 Hetzner Online GmbH" and geo.net_type == "hosting" and geo.cloud == "Hetzner"
    assert geo_from_mmdb_records(None, None).country == "Unknown"


def test_tor_list_parsing():
    assert parse_tor_list("# comment\n1.2.3.4\n\n5.6.7.8\n") == {"1.2.3.4", "5.6.7.8"}
