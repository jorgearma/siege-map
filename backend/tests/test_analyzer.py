"""Attack pattern, MITRE mapping and threat score."""
import pytest

from app.analyzer import classify, score_ip, severity_for
from app.models import MITRE_TTPS


@pytest.mark.parametrize("n_users, attempts, lines, expected, technique", [
    # few accounts, many tries each → guessing passwords for those accounts
    (1, 200, 400, "PASSWORD_GUESSING", "T1110.001"),
    (3, 90, 180, "PASSWORD_GUESSING", "T1110.001"),
    # many accounts, one or two tries each → spraying
    (40, 40, 80, "PASSWORD_SPRAYING", "T1110.003"),
    (25, 60, 120, "PASSWORD_SPRAYING", "T1110.003"),
    # many accounts AND many tries each → working through a user×password list
    (30, 600, 900, "DICTIONARY_ATTACK", "T1110.001"),
    (2, 1, 2, "SINGLE_PROBE", "T1110"),
])
def test_ssh_patterns(n_users, attempts, lines, expected, technique):
    pattern, ttps = classify(n_users, attempts, lines)
    assert pattern == expected
    assert technique in ttps


def test_spraying_is_many_accounts_not_few():
    """The mapping that used to be inverted: ≤3 usernames is NOT spraying."""
    assert classify(2, 300, 600)[0] != "PASSWORD_SPRAYING"
    assert classify(50, 50, 100)[0] == "PASSWORD_SPRAYING"


def test_no_account_tried_is_scanning_not_brute_force():
    pattern, ttps = classify(0, 0, 30)
    assert pattern == "SSH_SCANNING" and ttps == ["T1595"]


def test_http_only_address_is_web_scanning():
    pattern, ttps = classify(0, 0, 50, http_lines=50)
    assert pattern == "WEB_SCANNING" and ttps == ["T1595.002"]
    assert "T1190" in classify(0, 0, 50, http_lines=50, exploit=True)[1]


def test_every_emitted_technique_is_documented():
    cases = [classify(1, 50, 100), classify(40, 40, 80), classify(30, 600, 900),
             classify(0, 0, 30), classify(0, 0, 1), classify(2, 1, 2),
             classify(0, 0, 9, http_lines=9, exploit=True)]
    for _, ttps in cases:
        assert set(ttps) <= set(MITRE_TTPS)
    # Not observable from sshd logs: must never be claimed
    assert "T1110.004" not in MITRE_TTPS and "T1021.004" not in MITRE_TTPS


def test_score_is_not_capped_without_reputation():
    """An aggressive, persistent address reaches CRITICAL with no AbuseIPDB data."""
    s = score_ip(volume=800, rpm=40, breadth=80, days_active=6)
    assert s["score"] >= 75 and s["severity"] == "CRITICAL"


def test_single_probe_scores_low():
    s = score_ip(volume=1, rpm=0, breadth=1)
    assert s["score"] < 25 and s["severity"] == "LOW"


def test_reputation_moves_the_score_but_does_not_decide_it():
    base = dict(volume=200, rpm=15, breadth=20)
    clean, unknown, listed = (score_ip(**base, abuse_confidence=c)["score"] for c in (0, None, 100))
    assert clean < unknown < listed
    assert listed - clean == 15


def test_breakdown_adds_up_and_respects_its_maximums():
    s = score_ip(volume=5000, rpm=500, breadth=900, days_active=30,
                 exploit=True, multi_vector=True, abuse_confidence=100)
    assert s["score"] == 100
    assert all(0 <= p["points"] <= p["max"] for p in s["breakdown"])
    assert sum(p["max"] for p in s["breakdown"]) == 100


def test_severity_bands():
    assert [severity_for(x) for x in (0, 24, 25, 49, 50, 74, 75, 100)] == \
        ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"]
