#!/usr/bin/env python3
"""
Generates fake SSH log entries for testing SSH Bot Rain Map locally.

Usage:
    python scripts/fake_ssh_log.py [--output logs/auth.log] [--rate 2.0]

Options:
    --output    Path to write fake log entries (default: logs/auth.log)
    --rate      Average events per second (default: 2.0)
    --burst     Occasionally generate bursts of activity (flag)
"""

import argparse
import os
import random
import time
from datetime import datetime
from pathlib import Path

# Real-world IPs from various countries (public, well-known scanners/ranges)
ATTACKER_IPS = [
    # China
    "218.92.0.31", "222.186.15.101", "61.177.172.160", "121.18.238.109",
    "116.31.116.42", "182.100.67.112", "59.63.188.30", "123.249.24.233",
    # Russia
    "194.226.49.134", "95.142.39.97", "185.220.101.34", "77.247.181.162",
    "62.233.50.245", "45.145.66.127", "193.106.191.52", "91.240.118.172",
    # USA
    "192.241.XX.XX".replace("XX", str(random.randint(1, 254))),
    "104.248.45.12", "165.227.32.88", "68.183.120.55",
    # Brazil
    "177.222.138.89", "179.60.150.23", "200.137.65.100", "189.112.33.42",
    # India
    "103.99.0.110", "122.176.46.72", "59.94.235.11", "103.255.4.53",
    # South Korea
    "211.57.200.42", "121.138.172.50", "175.211.28.77", "61.43.155.98",
    # Vietnam
    "113.190.232.70", "14.161.28.115", "27.72.59.130", "103.45.234.8",
    # Germany
    "85.214.132.117", "178.254.10.44", "46.4.80.155", "138.201.52.90",
    # Netherlands
    "185.107.47.215", "89.248.167.131", "45.143.200.18", "193.32.162.70",
    # Iran
    "5.160.218.33", "185.55.225.110", "91.92.109.42", "5.63.15.118",
    # Indonesia
    "36.89.191.60", "103.31.38.89", "110.136.228.77", "180.244.162.35",
    # France
    "51.159.34.17", "163.172.154.108", "62.210.180.80", "195.154.46.35",
    # Japan
    "153.125.140.34", "133.130.108.67", "160.16.58.180", "49.212.155.45",
    # Argentina
    "181.46.212.15", "190.2.148.30", "200.45.69.71", "186.22.82.44",
    # Colombia
    "181.49.100.12", "190.248.33.55", "186.84.100.22", "200.69.111.8",
    # Mexico
    "189.203.45.60", "201.141.98.12", "187.188.45.77", "148.244.150.30",
]

# Common bot usernames
USERNAMES = [
    "root", "admin", "test", "user", "ubuntu", "oracle", "postgres",
    "mysql", "ftpuser", "guest", "pi", "ec2-user", "deploy", "git",
    "jenkins", "nagios", "zabbix", "ansible", "docker", "vagrant",
    "www", "www-data", "apache", "nginx", "tomcat", "redis",
    "minecraft", "teamspeak", "ts3", "csgo", "steam",
    "support", "info", "mail", "ftp", "backup", "operator",
    "student", "demo", "service", "samba", "hadoop", "spark",
    "elasticsearch", "kibana", "grafana", "prometheus",
    "administrator", "webmaster", "postmaster", "abuse",
    "test1", "test2", "user1", "user2", "admin1",
    "alex", "john", "dave", "mike", "bob", "tom", "maria",
]

# Event templates (syslog format)
TEMPLATES = [
    {
        "weight": 40,
        "format": "{ts} myserver sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2",
    },
    {
        "weight": 25,
        "format": "{ts} myserver sshd[{pid}]: Failed password for invalid user {user} from {ip} port {port} ssh2",
    },
    {
        "weight": 20,
        "format": "{ts} myserver sshd[{pid}]: Invalid user {user} from {ip} port {port}",
    },
    {
        "weight": 5,
        "format": "{ts} myserver sshd[{pid}]: Connection closed by authenticating user {user} {ip} port {port} [preauth]",
    },
    {
        "weight": 4,
        "format": "{ts} myserver sshd[{pid}]: Disconnected from authenticating user {user} {ip} port {port} [preauth]",
    },
    {
        "weight": 3,
        "format": "{ts} myserver sshd[{pid}]: error: maximum authentication attempts exceeded for invalid user {user} from {ip} port {port} ssh2",
    },
    {
        "weight": 2,
        "format": "{ts} myserver sshd[{pid}]: Received disconnect from {ip} port {port}:11: Bye Bye [preauth]",
    },
    {
        "weight": 1,
        "format": "{ts} myserver sshd[{pid}]: Bad protocol version identification '\\x03' from {ip} port {port}",
    },
]

# Build weighted list
WEIGHTED_TEMPLATES = []
for t in TEMPLATES:
    WEIGHTED_TEMPLATES.extend([t["format"]] * t["weight"])


def generate_line() -> str:
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    template = random.choice(WEIGHTED_TEMPLATES)
    return template.format(
        ts=ts,
        pid=random.randint(1000, 65000),
        user=random.choice(USERNAMES),
        ip=random.choice(ATTACKER_IPS),
        port=random.randint(30000, 65535),
    )


def main():
    parser = argparse.ArgumentParser(description="Generate fake SSH log entries")
    parser.add_argument(
        "--output", default="logs/auth.log", help="Output log file path"
    )
    parser.add_argument(
        "--rate", type=float, default=2.0, help="Average events per second"
    )
    parser.add_argument(
        "--burst", action="store_true", help="Enable random bursts"
    )
    args = parser.parse_args()

    # Ensure output directory exists
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Writing fake SSH logs to: {out_path.resolve()}")
    print(f"Rate: ~{args.rate} events/sec {'(with bursts)' if args.burst else ''}")
    print("Press Ctrl+C to stop\n")

    count = 0
    try:
        with open(out_path, "a") as f:
            while True:
                # Generate one or more lines
                if args.burst and random.random() < 0.05:
                    # Burst: 5-20 events from the same IP rapidly
                    burst_ip = random.choice(ATTACKER_IPS)
                    burst_user = random.choice(USERNAMES)
                    burst_count = random.randint(5, 20)
                    for _ in range(burst_count):
                        ts = datetime.now().strftime("%b %d %H:%M:%S")
                        line = random.choice(WEIGHTED_TEMPLATES).format(
                            ts=ts,
                            pid=random.randint(1000, 65000),
                            user=burst_user,
                            ip=burst_ip,
                            port=random.randint(30000, 65535),
                        )
                        f.write(line + "\n")
                        f.flush()
                        count += 1
                        print(f"\r[BURST] Events: {count}", end="", flush=True)
                        time.sleep(random.uniform(0.05, 0.2))
                else:
                    line = generate_line()
                    f.write(line + "\n")
                    f.flush()
                    count += 1
                    print(f"\rEvents generated: {count}", end="", flush=True)

                # Random delay based on rate
                delay = random.expovariate(args.rate)
                delay = min(delay, 5.0)  # cap at 5 seconds
                time.sleep(delay)

    except KeyboardInterrupt:
        print(f"\n\nStopped. Total events written: {count}")
        print(f"Log file: {out_path.resolve()}")


if __name__ == "__main__":
    main()
