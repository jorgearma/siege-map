"""
Campaign detection against synthetic traffic: a real botnet hidden in the
usual background of unrelated bots. The point of these tests is the false
positives — the background must NOT come out as a coordinated campaign.
"""
import random
from datetime import datetime, timedelta

import pytest

from app import campaigns
from app.db import Database
from app.models import GeoInfo, SSHEvent

NOW = datetime.now().replace(microsecond=0)
CLOUDS = ["DigitalOcean", "Tencent", "Hetzner", "OVH", "Alibaba", "Linode", "Contabo", "Vultr"]


@pytest.fixture
def db():
    campaigns._cache.clear()
    return Database(":memory:", prefix_len=4)


def attack(db, ip, usernames, at, org="DigitalOcean", cc="US", n=[0]):
    """One address trying `usernames` in order, one attempt each."""
    for i, user in enumerate(usernames):
        n[0] += 1
        e = SSHEvent(timestamp=(at + timedelta(seconds=i)).isoformat(), ip=ip, username=user,
                     event_type="failed_password", raw_line="", id=f"c{n[0]}",
                     geo=GeoInfo(cc, cc, "x", 0, 0, org, org, "hosting", org), attempts=1)
        db.touch_ip(e, lines=1, attempts=1)
        db.save_event(e)


def background(db, rng, count=60):
    """Unrelated bots: everyone tries root/admin, each with its own list, over a week."""
    pool = ["root", "admin", "user", "test", "ubuntu", "oracle", "postgres", "git", "pi", "ftp"]
    for i in range(count):
        users = ["root", "admin"] + rng.sample(pool[2:], 2) + [f"u{i}"]
        rng.shuffle(users)
        attack(db, f"{rng.randint(11, 200)}.{rng.randint(1, 250)}.{i}.7", users,
               NOW - timedelta(hours=rng.randint(1, 160)),
               org=rng.choice(CLOUDS), cc=rng.choice(["US", "CN", "DE", "BR", "IN"]))


def shared_default_wordlist(db, rng, count=30):
    """Same popular tool, same default list — but unrelated machines over days."""
    for i in range(count):
        attack(db, f"{rng.randint(11, 200)}.{i}.{rng.randint(1, 250)}.9",
               ["root", "admin", "user", "test", "ubuntu"],
               NOW - timedelta(hours=5 * i + 2),
               org=rng.choice(CLOUDS), cc=rng.choice(["US", "CN", "DE", "BR", "IN"]))


def botnet(db, count=12):
    """One operator: a rare wordlist, one rented /24, all arriving in 20 minutes."""
    for i in range(count):
        attack(db, f"45.9.10.{i + 1}", ["zx_miner", "oracle19", "svc_k8s", "deploy77", "root"],
               NOW - timedelta(minutes=40) + timedelta(minutes=i * 1.5), org="ShadyHost", cc="NL")


def by_users(found, first, second=None):
    return next(c for c in found if c["usernames"][0] == first
                and (second is None or c["usernames"][1] == second))


def test_real_botnet_is_high_confidence(db):
    rng = random.Random(7)
    background(db, rng)
    botnet(db)
    db.flush()
    c = by_users(campaigns.detect(db), "zx_miner")
    assert c["ips"] == 12
    assert c["level"] == "HIGH" and c["label"] == "coordinated campaign"
    assert all(v >= 0.5 for v in c["signals"].values())
    assert c["active"]


def test_shared_default_wordlist_is_not_a_campaign(db):
    """The false positive this module exists to avoid."""
    rng = random.Random(7)
    background(db, rng)
    shared_default_wordlist(db, rng)
    botnet(db)
    db.flush()
    found = campaigns.detect(db)
    common = next(c for c in found if c["usernames"] == ["root", "admin", "user", "test"])
    assert common["ips"] >= 30
    assert common["level"] == "LOW" and common["label"] == "shared tooling"
    # More addresses, yet ranked below the real one
    assert found.index(by_users(found, "zx_miner")) < found.index(common)


def test_one_signal_alone_never_reaches_high():
    # Perfect timing, nothing else
    score, level = campaigns.confidence({"specificity": 0.0, "timing": 1.0, "network": 0.0}, 50)
    assert level != "HIGH"
    # Rare wordlist, but spread over time and networks
    score, level = campaigns.confidence({"specificity": 1.0, "timing": 0.1, "network": 0.0}, 50)
    assert level == "MEDIUM" and score < campaigns.HIGH_AT


def test_a_pair_is_weaker_evidence_than_a_crowd():
    signals = {"specificity": 1.0, "timing": 1.0, "network": 0.0}
    pair, _ = campaigns.confidence(signals, 2)
    crowd, _ = campaigns.confidence(signals, 20)
    assert pair < crowd


def test_rarity_is_measured_against_the_other_addresses():
    assert campaigns.rarity(0, 500) == 1.0          # nobody else uses it
    assert campaigns.rarity(400, 500) == 0.0        # everybody does
    assert 0 < campaigns.rarity(10, 500) < 1
    assert campaigns.rarity(0, 0) == 0.5            # nothing to compare: neutral


def test_timing_signal():
    burst = [(NOW + timedelta(minutes=i)).isoformat() for i in range(10)]
    spread = [(NOW + timedelta(hours=7 * i)).isoformat() for i in range(10)]
    assert campaigns.timing_signal(burst) == 1.0
    assert campaigns.timing_signal(spread) == 0.1


def test_network_signal_prefers_shared_ranges_over_big_clouds():
    same_24 = campaigns.network_signal(["1.2.3.xxx"] * 6, ["A", "B", "C", "D", "E", "F"])
    same_cloud = campaigns.network_signal([f"1.2.{i}.xxx" for i in range(6)], ["DigitalOcean"] * 6)
    nothing = campaigns.network_signal([f"1.2.{i}.xxx" for i in range(6)], list("ABCDEF"))
    assert same_24 == 1.0 and nothing == 0.0
    assert 0 < same_cloud < same_24


def test_distributed_spray_is_caught_without_a_wordlist(db):
    """Each machine tries ONE user: no prefix, but 9 machines in ten minutes."""
    slot = NOW.replace(minute=NOW.minute // 10 * 10, second=0) - timedelta(minutes=30)
    # Baseline: this account gets one visitor per slot; root gets six, always
    for b in range(1, 13):
        at = slot - timedelta(minutes=10 * b)
        attack(db, f"99.1.{b}.1", ["svc_backup"], at)
        for i in range(6):
            attack(db, f"77.{b}.{i}.1", ["root"], at + timedelta(seconds=10 * i))
    for i in range(6):
        attack(db, f"78.1.{i}.1", ["root"], slot + timedelta(seconds=10 * i))
    for i in range(9):
        attack(db, f"61.{i + 1}.5.1", ["svc_backup"], slot + timedelta(seconds=20 * i), cc="RU")
    db.flush()

    bursts = campaigns.distributed_bursts(db)
    assert [b["usernames"] for b in bursts] == [["svc_backup"]]   # root: business as usual
    b = bursts[0]
    assert b["kind"] == "distributed_spray" and b["ips"] == 9
    assert b["baseline_ips"] == 1 and b["level"] in ("MEDIUM", "HIGH")
    # None of those addresses has a wordlist fingerprint
    assert campaigns.wordlist_campaigns(db) == []


def test_general_traffic_spike_is_not_one_spray_per_username(db):
    """Everything triples at once: that is a burst, not a targeted spray."""
    slot = NOW.replace(minute=NOW.minute // 10 * 10, second=0) - timedelta(minutes=30)
    users = ["root", "admin", "git", "oracle"]
    for b in range(1, 13):                                   # usual: 2 addresses per user
        for u, user in enumerate(users):
            for i in range(2):
                attack(db, f"70.{b}.{u}.{i + 1}", [user], slot - timedelta(minutes=10 * b))
    for u, user in enumerate(users):                         # spike: 12 per user, all users
        for i in range(12):
            attack(db, f"71.{u}.{i}.1", [user], slot + timedelta(seconds=10 * i))
    db.flush()
    assert campaigns.distributed_bursts(db) == []
