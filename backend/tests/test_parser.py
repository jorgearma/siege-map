from app.parser import parse_line, is_private_ip

TS = "Nov 15 10:00:00 vps"


def test_failed_password_invalid_user():
    e = parse_line(f"{TS} sshd[101]: Failed password for invalid user admin from 8.8.4.4 port 4242 ssh2")
    assert (e.event_type, e.username, e.ip) == ("failed_password", "admin", "8.8.4.4")


def test_documentation_range_is_not_public():
    assert parse_line(f"{TS} sshd[101]: Failed password for root from 203.0.113.9 port 4242 ssh2") is None


def test_public_ip_is_parsed():
    e = parse_line(f"{TS} sshd[101]: Failed password for root from 8.8.8.8 port 4242 ssh2")
    assert (e.event_type, e.username, e.ip) == ("failed_password", "root", "8.8.8.8")


def test_openssh_98_process_name():
    """OpenSSH >= 9.8 logs from sshd-session, not sshd."""
    e = parse_line(f"{TS} sshd-session[101]: Invalid user pi from 8.8.8.8 port 4242")
    assert e and e.event_type == "invalid_user" and e.username == "pi"


def test_systemd_timestamp():
    e = parse_line("2026-11-15T10:00:00.123456+01:00 vps sshd[9]: Invalid user git from 1.1.1.1 port 22")
    # +01:00 is CONVERTED to the process's time zone (UTC in the tests), not
    # stripped: otherwise a host in +01:00 and a container in UTC disagree
    assert e.timestamp.startswith("2026-11-15T09:00:00")
    assert "+" not in e.timestamp  # naive, like every other timestamp


def test_ipv6():
    e = parse_line(f"{TS} sshd[101]: Failed password for root from 2606:4700:4700::1111 port 4242 ssh2")
    assert e and e.ip == "2606:4700:4700::1111"


def test_private_and_loopback_are_skipped():
    assert parse_line(f"{TS} sshd[1]: Failed password for root from 192.168.1.5 port 1 ssh2") is None
    assert parse_line(f"{TS} sshd[1]: Failed password for root from ::1 port 1 ssh2") is None
    assert is_private_ip("10.0.0.1") and is_private_ip("fe80::1") and not is_private_ip("8.8.8.8")


def test_connection_closed_variants():
    a = parse_line(f"{TS} sshd[1]: Connection closed by authenticating user root 8.8.8.8 port 5 [preauth]")
    b = parse_line(f"{TS} sshd[1]: Connection closed by invalid user oracle 8.8.8.8 port 5 [preauth]")
    c = parse_line(f"{TS} sshd[1]: Connection closed by 8.8.8.8 port 5 [preauth]")
    assert (a.username, b.username, c.username) == ("root", "oracle", "(none)")
    assert a.event_type == b.event_type == c.event_type == "connection_closed"


def test_bad_protocol_keeps_what_the_client_sent():
    e = parse_line(f"{TS} sshd[1]: Bad protocol version identification 'GET / HTTP/1.1' from 8.8.8.8 port 5")
    assert e.event_type == "bad_protocol" and e.meta["banner"] == "GET / HTTP/1.1"


def test_banner_exchange_wording():
    e = parse_line(f"{TS} sshd[1]: banner exchange: Connection from 8.8.8.8 port 5: invalid format")
    assert e.event_type == "bad_protocol" and e.meta["banner"] == "invalid format"


def test_kex_mismatch_offer():
    e = parse_line(
        f"{TS} sshd[1]: Unable to negotiate with 8.8.8.8 port 5: no matching key exchange method found. "
        "Their offer: diffie-hellman-group1-sha1,diffie-hellman-group14-sha1 [preauth]"
    )
    assert e.event_type == "kex_mismatch"
    assert e.meta["kex"].startswith("diffie-hellman-group1-sha1")


def test_unrelated_lines():
    assert parse_line(f"{TS} CRON[1]: pam_unix(cron:session): session opened") is None
    assert parse_line(f"{TS} sshd[1]: Accepted publickey for jorge from 8.8.8.8 port 5 ssh2") is None
    assert parse_line("") is None


def test_control_characters_are_neutralised():
    e = parse_line(f"{TS} sshd[1]: Invalid user a\x1b[31mb from 8.8.8.8 port 5")
    assert "\x1b" not in e.username
